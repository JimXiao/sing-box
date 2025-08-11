package adblock

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/md5"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	mDNS "github.com/miekg/dns"
	"github.com/sagernet/sing-box/adapter"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/dns"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	R "github.com/sagernet/sing-box/route/rule"
)

type AdBlockManager struct {
	initOnce  sync.Once
	mu        sync.RWMutex
	ctx       context.Context
	cancel    context.CancelFunc
	running   bool
	logger    log.ContextLogger
	config    *option.AdblockOption
	lastMD5   string
	domains   []string
	dnsRouter *dns.Router
	hasInjected bool
}

var singleton *AdBlockManager
var once sync.Once

func instance() *AdBlockManager {
	once.Do(func() {
		singleton = &AdBlockManager{}
	})
	return singleton
}

func Start(logger log.ContextLogger, router *dns.Router, config *option.AdblockOption) {
	logger.Debug("[adBlock] Start called")
	if singleton == nil {
		logger.Debug("[adBlock] Singleton nil return")
		return
	}
	logger.Debug("[adBlock] To Start adblock ")
	singleton.Start(logger, router, config)
}	

func Stop() {
	if singleton == nil {
		return
	}
	singleton.Stop()
}

func (m *AdBlockManager) Start(logger log.ContextLogger, router *dns.Router, config *option.AdblockOption) {
	logger.Debug("[adBlock] Ready to Start loop")
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.running {
		m.logger.Debug("[adBlock] already running, return...")
		return
	}
	m.logger = logger
	m.dnsRouter = router
	m.config = config
	m.hasInjected = false
	m.logger.Debug("[adBlock] Starting loop")
	m.ctx, m.cancel = context.WithCancel(context.Background())
	m.running = true
	m.hijackAdBlockDomainsToRouter()

	go m.loop()
}

func (m *AdBlockManager) Stop() {
	m.logger.Debug("[adBlock] Ready to Stop loop")
	m.mu.Lock()
	defer m.mu.Unlock()
	m.hasInjected = false
	if m.running {
		m.logger.Debug("[adBlock] Stopping loop")
		m.cancel()
		m.running = false
	}
}

func (m *AdBlockManager) loop() {
	m.logger.Debug("[adBlock] Entering loop")
	m.pull()
	ticker := time.NewTicker(time.Duration(m.config.Interval))
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			m.pull()
		case <-m.ctx.Done():
			m.logger.Debug("[adBlock] Loop exited")
			return
		}
	}
}

func RegisterToRouter(logger log.ContextLogger, router *dns.Router, config *option.AdblockOption) {
	logger.Debug("[adBlock] Trying to Instance AdblockManager ")
	instance()
	Start(logger, router, config)
}

func (m *AdBlockManager) getNewDnsRules() option.DNSRule {
	rc := option.DNSRCode(dns.RcodeNameError)

	rule := option.DNSRule{
		Type: C.RuleTypeDefault,
		DefaultOptions: option.DefaultDNSRule{
			RawDefaultDNSRule: option.RawDefaultDNSRule{
				DomainSuffix: m.domains,
			},
			DNSRuleAction: option.DNSRuleAction{},
		},
	}
	rule.DefaultOptions.DNSRuleAction.Action = C.RuleActionTypePredefined
	rule.DefaultOptions.DNSRuleAction.PredefinedOptions.Rcode = &rc

	return rule
}

func (m *AdBlockManager) pull() {
	var (
		success bool
		body    []byte
	)

	for _, url := range m.config.URLs {
		requestUrl := url
		if strings.Contains(requestUrl, "?") {
			requestUrl = fmt.Sprintf("%s&md5=%s", requestUrl, m.lastMD5)
		} else {
			requestUrl = fmt.Sprintf("%s?md5=%s", requestUrl, m.lastMD5)
		}
		m.logger.Debug("[adBlock] Trying to pull adblock list from: ", requestUrl)
		client := &http.Client{
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				if len(via) > 0 {
					req.Header = via[0].Header
				}
				return nil
			},
		}	

		resp, err := client.Get(requestUrl)
		if err != nil {
			m.logger.Warn("[adBlock] Failed to fetch from ", url, ": ", err)
			continue
		}

		if resp.StatusCode != 200 {
			if resp.StatusCode == http.StatusNoContent {
				m.logger.Debug("[adBlock] adblock osid file is up todate")
				resp.Body.Close()
				return
			}
			m.logger.Warn("[adBlock] Unexpected status code from ", url, ": ", resp.StatusCode)
			continue
		}
		body, err = io.ReadAll(resp.Body)
		if err != nil {
			m.logger.Warn("[adBlock] Failed to fetch from body", url, ": ", err)
			continue
		}
		success = true
		break
	}

	if !success {
		m.logger.Warn("[adBlock] All URLs failed to fetch adblock list, will retry on next interval")
		return
	}

	sum := md5.Sum(body)
	newMD5 := hex.EncodeToString(sum[:])
	if newMD5 == m.lastMD5 && m.hasInjected  {
		m.logger.Debug("[adBlock] adblock list not changed (MD5 matched)")
		return
	}

	domains := m.parseOISDZip(body)
	if len(domains) == 0 {
		m.logger.Warn("[adBlock] No valid domains extracted from zip")
		return
	}
	m.logger.Debug("[adBlock] Pulled new adblock list with ", len(domains), " domains, MD5: ", newMD5)
	m.printDomainPreview(domains)

	m.mu.Lock()
	m.lastMD5 = newMD5
	m.domains = domains
	m.hasInjected = false
	m.mu.Unlock()

	if m.dnsRouter != nil && m.config.Enable {
		m.logger.Debug("[adBlock] Injecting new domains into live dnsRouter")
		m.hijackAdBlockDomainsToRouter()
	} else {
		m.logger.Debug("[adBlock] DNSRouter not available or is not enable, skipping live injection")
	}
}

func (m *AdBlockManager) printDomainPreview(domains []string) {
	const previewCount = 10
	n := len(domains)
	if n == 0 {
		m.logger.Debug("[domain debug] domain list is empty")
		return
	}

	limit := previewCount
	if n < previewCount {
		limit = n
	}

	m.logger.Debug("[domain debug] total domains: ", n)
	for i := 0; i < limit; i++ {
		m.logger.Debug(domains[i])
	}
	if n > limit {
		m.logger.Debug(fmt.Sprintf("  ... (truncated, %d more)\n", n-limit))
	}
}

func (m *AdBlockManager) hijackAdBlockDomainsToRouter() {
	if m.hasInjected {
		m.logger.Warn("[adBlock] hijackAdBlockDomainsToRouter already done. this turn skip")
		return
	}

	if len(m.domains) == 0 {
		m.logger.Warn("[adBlock] hijackAdBlockDomainsToRouter skip cause by len(domains) == 0")
		return
	}

	if m.dnsRouter == nil {
		m.logger.Error("[adBlock] dnsRouter is nil, cannot inject")
		return
	}

	newRule, err := R.NewDNSRule(m.ctx, m.logger, m.getNewDnsRules(), true)
	if err != nil {
		m.logger.Error("[adBlock] Failed to rebuild DNSRule: ", err)
		return
	}

	rp := m.dnsRouter.GetRules()
	rules := *rp

	replaced := false
	for i, raw := range rules {
		def, ok := raw.(*R.DefaultDNSRule)
		if !ok {
			continue
		}
		if act, ok := def.Action().(*R.RuleActionPredefined); ok && act.Rcode != mDNS.RcodeNameError {
			rules[i] = newRule
			replaced = true
			m.logger.Debug("[adBlock] Replaced adblock rule at index ", i)
			break
		}
	}

	if replaced {
		*rp = rules
	} else {
		newRules := make([]adapter.DNSRule, 0, len(rules)+1)
		newRules = append(newRules, newRule)
		newRules = append(newRules, rules...)
		*rp = newRules
		m.logger.Debug("[adBlock] prepended new adblock rule, total=", len(newRules))
	}

	m.dnsRouter.ClearCache()
	m.hasInjected = true;
	m.logger.Warn("[adBlock] hijackAdBlockDomainsToRouter done")
}

func (m *AdBlockManager) parseOISDZip(data []byte) []string {
	var domains []string
	reader, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		m.logger.Warn("[adBlock] Failed to unzip:", err)
		return nil
	}

	for _, file := range reader.File {
		rc, err := file.Open()
		if err != nil {
			m.logger.Warn("[adBlock] Failed to open zip file:", err)
			continue
		}
		defer rc.Close()

		buf := new(bytes.Buffer)
		if _, err := buf.ReadFrom(rc); err != nil {
			m.logger.Warn("[adBlock] Failed to read zip content:", err)
			continue
		}

		lines := strings.Split(buf.String(), "\n")
		for _, raw := range lines {
			line := strings.TrimSpace(raw)
			if line == "" || strings.HasPrefix(line, "!") {
				continue
			}

			if strings.HasPrefix(line, "||") {
				domain := strings.TrimPrefix(line, "||")
				domain = strings.TrimSuffix(domain, "^")
				domain = strings.TrimSuffix(domain, "/")
				domain = strings.TrimSpace(domain)

				if domain == "" || strings.Contains(domain, "/") || strings.Contains(domain, "^") {
					continue
				}
				domains = append(domains, domain)
			}
		}
	}

	if len(domains) > 0 {
		m.logger.Debug("[adBlock] Extracted domain count:", len(domains))
	} else {
		m.logger.Warn("[adBlock] No valid domain lines found in zip")
	}

	return domains
}

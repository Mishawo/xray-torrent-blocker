package firewall

import (
    "bytes"
    "fmt"
    "log"
    "net"

    "github.com/google/nftables"
    "github.com/google/nftables/expr"
)

const (
    nftTableName   = "tblocker"
    nftChainName   = "TBLOCKER_BLOCKED"
    nftSetNameIPv4 = "TBLOCKER_BLOCKED_IPS"
    nftSetNameIPv6 = "TBLOCKER_BLOCKED_IPS6"
)

type NFTFirewall struct {
    conn        *nftables.Conn
    initialized bool
}

func NewNFTFirewall() *NFTFirewall {
    return &NFTFirewall{
        conn:        &nftables.Conn{},
        initialized: false,
    }
}

func (f *NFTFirewall) Initialize() error {
    if f.initialized {
        return nil
    }

    log.Printf("Initializing nftables firewall...")

    table := &nftables.Table{
        Family: nftables.TableFamilyINet,
        Name:   nftTableName,
    }
    f.conn.AddTable(table)

    policy := nftables.ChainPolicyAccept
    chain := &nftables.Chain{
        Name:     nftChainName,
        Table:    table,
        Type:     nftables.ChainTypeFilter,
        Hooknum:  nftables.ChainHookPrerouting,
        Priority: nftables.ChainPriorityFilter,
        Policy:   &policy,
    }
    f.conn.AddChain(chain)

    set4 := &nftables.Set{
        Table:   table,
        Name:    nftSetNameIPv4,
        KeyType: nftables.TypeIPAddr,
    }
    f.conn.AddSet(set4, []nftables.SetElement{})

    set6 := &nftables.Set{
        Table:   table,
        Name:    nftSetNameIPv6,
        KeyType: nftables.TypeIP6Addr,
    }
    f.conn.AddSet(set6, []nftables.SetElement{})

    // IPv4 source address drop rule (network header offset 12, 4 bytes)
    if !f.dropRuleExists(table, chain, nftSetNameIPv4, 12, 4) {
        f.conn.AddRule(&nftables.Rule{
            Table: table,
            Chain: chain,
            Exprs: []expr.Any{
                &expr.Payload{
                    DestRegister: 1,
                    Base:         expr.PayloadBaseNetworkHeader,
                    Offset:       12,
                    Len:          4,
                },
                &expr.Lookup{
                    SourceRegister: 1,
                    SetName:        nftSetNameIPv4,
                    SetID:          set4.ID,
                },
                &expr.Verdict{
                    Kind: expr.VerdictDrop,
                },
            },
        })
        log.Printf("IPv4 drop rule added to nftables")
    } else {
        log.Printf("IPv4 drop rule already exists in nftables")
    }

    // IPv6 source address drop rule (network header offset 8, 16 bytes)
    if !f.dropRuleExists(table, chain, nftSetNameIPv6, 8, 16) {
        f.conn.AddRule(&nftables.Rule{
            Table: table,
            Chain: chain,
            Exprs: []expr.Any{
                &expr.Payload{
                    DestRegister: 1,
                    Base:         expr.PayloadBaseNetworkHeader,
                    Offset:       8,
                    Len:          16,
                },
                &expr.Lookup{
                    SourceRegister: 1,
                    SetName:        nftSetNameIPv6,
                    SetID:          set6.ID,
                },
                &expr.Verdict{
                    Kind: expr.VerdictDrop,
                },
            },
        })
        log.Printf("IPv6 drop rule added to nftables")
    } else {
        log.Printf("IPv6 drop rule already exists in nftables")
    }

    err := f.conn.Flush()
    if err != nil {
        log.Printf("Error initializing nftables: %v", err)
        return fmt.Errorf("failed to initialize nftables: %v", err)
    }

    log.Printf("Nftables firewall initialized successfully")
    f.initialized = true
    return nil
}

// dropRuleExists checks whether a payload -> lookup -> verdict(DROP) rule for
// the given set and source-address offset already exists in the chain.
func (f *NFTFirewall) dropRuleExists(table *nftables.Table, chain *nftables.Chain, setName string, payloadOffset, payloadLen uint32) bool {
    rules, err := f.conn.GetRules(table, chain)
    if err != nil {
        log.Printf("Error checking existing nftables rules: %v", err)
        return false
    }

    for _, rule := range rules {
        if len(rule.Exprs) < 3 {
            continue
        }

        payload, okPayload := rule.Exprs[0].(*expr.Payload)
        lookup, okLookup := rule.Exprs[1].(*expr.Lookup)
        verdict, okVerdict := rule.Exprs[2].(*expr.Verdict)

        if okPayload && okLookup && okVerdict &&
            payload.DestRegister == 1 &&
            payload.Base == expr.PayloadBaseNetworkHeader &&
            payload.Offset == payloadOffset &&
            payload.Len == payloadLen &&
            lookup.SourceRegister == 1 &&
            lookup.SetName == setName &&
            verdict.Kind == expr.VerdictDrop {
            return true
        }
    }
    return false
}

// setForIP returns the nftables set (and the element key) matching the IP
// family of the given address.
func setForIP(ip net.IP) (*nftables.Set, []byte) {
    table := &nftables.Table{
        Family: nftables.TableFamilyINet,
        Name:   nftTableName,
    }

    if ip.To4() != nil {
        return &nftables.Set{
            Table:   table,
            Name:    nftSetNameIPv4,
            KeyType: nftables.TypeIPAddr,
        }, ip.To4()
    }

    return &nftables.Set{
        Table:   table,
        Name:    nftSetNameIPv6,
        KeyType: nftables.TypeIP6Addr,
    }, ip.To16()
}

func (f *NFTFirewall) BlockIP(ip string) error {
    parsedIP := net.ParseIP(ip)
    if parsedIP == nil {
        return fmt.Errorf("invalid IP address: %s", ip)
    }

    if !f.initialized {
        if err := f.Initialize(); err != nil {
            return fmt.Errorf("failed to initialize firewall: %v", err)
        }
    }

    set, key := setForIP(parsedIP)
    f.conn.SetAddElements(set, []nftables.SetElement{{Key: key}})

    if err := f.conn.Flush(); err != nil {
        log.Printf("Error adding IP %s to nftables set: %v", ip, err)
        return fmt.Errorf("failed to add IP %s to nftables set: %v", ip, err)
    }

    log.Printf("IP %s blocked with nftables", ip)
    return nil
}

func (f *NFTFirewall) UnblockIP(ip string) error {
    parsedIP := net.ParseIP(ip)
    if parsedIP == nil {
        return fmt.Errorf("invalid IP address: %s", ip)
    }

    set, key := setForIP(parsedIP)

    f.conn.SetDeleteElements(set, []nftables.SetElement{{Key: key}})

    if err := f.conn.Flush(); err != nil {
        // If the IP is no longer in the set, the unblock effectively already
        // happened - treat it as success so storage cleanup can proceed.
        if !f.isIPInSet(set.Name, key) {
            log.Printf("IP %s already unblocked with nftables", ip)
            return nil
        }

        log.Printf("Error unblocking IP %s with nftables: %v", ip, err)
        return fmt.Errorf("failed to unblock IP %s with nftables: %v", ip, err)
    }

    log.Printf("IP %s unblocked with nftables", ip)
    return nil
}

// isIPInSet reports whether key is currently present in the named set.
func (f *NFTFirewall) isIPInSet(setName string, key []byte) bool {
    table := &nftables.Table{
        Family: nftables.TableFamilyINet,
        Name:   nftTableName,
    }

    sets, err := f.conn.GetSets(table)
    if err != nil {
        log.Printf("Warning: could not verify nftables set contents: %v", err)
        return false
    }

    for _, s := range sets {
        if s.Name != setName {
            continue
        }

        elements, err := f.conn.GetSetElements(s)
        if err != nil {
            log.Printf("Warning: could not list nftables set %s: %v", setName, err)
            return false
        }

        for _, element := range elements {
            if bytes.Equal(element.Key, key) {
                return true
            }
        }
        return false
    }
    return false
}

func (f *NFTFirewall) GetBlockedIPs() (map[string]bool, error) {
    table := &nftables.Table{
        Family: nftables.TableFamilyINet,
        Name:   nftTableName,
    }

    sets, err := f.conn.GetSets(table)
    if err != nil {
        log.Printf("Error getting sets via API: %v", err)
        return nil, fmt.Errorf("failed to get sets via API: %v", err)
    }

    blockedIPs := make(map[string]bool)
    for _, s := range sets {
        if s.Name != nftSetNameIPv4 && s.Name != nftSetNameIPv6 {
            continue
        }

        elements, err := f.conn.GetSetElements(s)
        if err != nil {
            log.Printf("Warning: could not list nftables set %s: %v", s.Name, err)
            continue
        }

        for _, element := range elements {
            switch len(element.Key) {
            case 4, 16:
                blockedIPs[net.IP(element.Key).String()] = true
            }
        }
    }

    return blockedIPs, nil
}

func (f *NFTFirewall) IsAvailable() bool {
    return isCommandAvailable("nft")
}

func (f *NFTFirewall) GetName() string {
    return "nftables"
}

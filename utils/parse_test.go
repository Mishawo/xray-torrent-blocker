package utils

import (
    "testing"

    "tblocker/config"
)

func setupParseTest() {
    config.TorrentTag = "TORRENT"
    initializeByteSearchPatterns()
}

func TestParseLogEntryFastIPv4(t *testing.T) {
    setupParseTest()

    line := `[TORRENT] 2025/10/18 12:00:00 from 1.2.3.4:51170 accepted tcp:example.com:443 [inbound -> direct] email: alice`
    ip, user, valid := parseLogEntryFast(line)

    if !valid {
        t.Fatalf("expected valid parse for IPv4 line")
    }
    if ip != "1.2.3.4" {
        t.Errorf("expected ip '1.2.3.4', got '%s'", ip)
    }
    if user != "alice" {
        t.Errorf("expected user 'alice', got '%s'", user)
    }
}

func TestParseLogEntryFastIPv4WithProtocolPrefix(t *testing.T) {
    setupParseTest()

    line := `[TORRENT] 2025/10/18 12:00:00 from tcp:5.6.7.8:1000 accepted udp:tracker.example.com:53 [inbound -> direct] email: bob`
    ip, user, valid := parseLogEntryFast(line)

    if !valid {
        t.Fatalf("expected valid parse for IPv4 line with tcp: prefix")
    }
    if ip != "5.6.7.8" {
        t.Errorf("expected ip '5.6.7.8', got '%s'", ip)
    }
    if user != "bob" {
        t.Errorf("expected user 'bob', got '%s'", user)
    }
}

func TestParseLogEntryFastIPv6(t *testing.T) {
    setupParseTest()

    line := `[TORRENT] 2025/10/18 12:00:00 from [2001:db8::1]:443 accepted tcp:example.com:443 [inbound -> direct] email: carol`
    ip, user, valid := parseLogEntryFast(line)

    if !valid {
        t.Fatalf("expected valid parse for IPv6 line")
    }
    if ip != "2001:db8::1" {
        t.Errorf("expected ip '2001:db8::1', got '%s'", ip)
    }
    if user != "carol" {
        t.Errorf("expected user 'carol', got '%s'", user)
    }
}

func TestParseLogEntryFastIPv6UppercaseCanonicalized(t *testing.T) {
    setupParseTest()

    line := `[TORRENT] 2025/10/18 12:00:00 from [2001:DB8::ABCD]:443 accepted tcp:example.com:443 [inbound -> direct] email: erin`
    ip, _, valid := parseLogEntryFast(line)

    if !valid {
        t.Fatalf("expected valid parse for uppercase IPv6 line")
    }
    if ip != "2001:db8::abcd" {
        t.Errorf("expected canonical ip '2001:db8::abcd', got '%s'", ip)
    }
}

func TestParseLogEntryFastIPv4MappedIPv6(t *testing.T) {
    setupParseTest()

    line := `[TORRENT] 2025/10/18 12:00:00 from tcp:[::ffff:192.168.1.5]:8443 accepted tcp:example.com:443 [inbound -> direct] email: dave`
    ip, _, valid := parseLogEntryFast(line)

    if !valid {
        t.Fatalf("expected valid parse for IPv4-mapped IPv6 line")
    }
    if ip != "192.168.1.5" {
        t.Errorf("expected mapped ip '192.168.1.5', got '%s'", ip)
    }
}

func TestParseLogEntryFastInvalidCases(t *testing.T) {
    setupParseTest()

    cases := []struct {
        name string
        line string
    }{
        {"no torrent tag", `2025/10/18 12:00:00 from 1.2.3.4:51170 accepted tcp:example.com:443 email: alice`},
        {"no ip", `[TORRENT] 2025/10/18 12:00:00 accepted tcp:example.com:443 email: alice`},
        {"garbage ip", `[TORRENT] 2025/10/18 12:00:00 from notanip:123 accepted tcp:example.com:443 email: alice`},
        {"garbage ipv6", `[TORRENT] 2025/10/18 12:00:00 from [2001:zzzz::1]:443 accepted tcp:example.com:443 email: alice`},
        {"unclosed bracket", `[TORRENT] 2025/10/18 12:00:00 from [2001:db8::1:443 accepted tcp:example.com:443 email: alice`},
        {"no username", `[TORRENT] 2025/10/18 12:00:00 from 1.2.3.4:51170 accepted tcp:example.com:443`},
        {"ipv4 out of range", `[TORRENT] 2025/10/18 12:00:00 from 999.999.999.999:51170 accepted tcp:example.com:443 email: alice`},
    }

    for _, tc := range cases {
        t.Run(tc.name, func(t *testing.T) {
            ip, user, valid := parseLogEntryFast(tc.line)
            if valid {
                t.Errorf("expected invalid parse, got ip='%s' user='%s'", ip, user)
            }
        })
    }
}

func TestParseLogEntryFastIPv6ShortForm(t *testing.T) {
    setupParseTest()

    line := `[TORRENT] 2025/10/18 12:00:00 from [::1]:443 accepted tcp:localhost:443 [inbound -> direct] email: frank`
    ip, _, valid := parseLogEntryFast(line)

    if !valid {
        t.Fatalf("expected valid parse for ::1")
    }
    if ip != "::1" {
        t.Errorf("expected ip '::1', got '%s'", ip)
    }
}

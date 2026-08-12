package config

import (
    "fmt"
    "log"
    "os"
    "regexp"
    "time"

    "gopkg.in/yaml.v2"
)

var (
    LogFile       string
    BlockDuration int
    TorrentTag    string
    BlockMode     string
    BypassIPSet   = make(map[string]struct{})
    StorageDir    string

    SendWebhook     bool
    WebhookURL      string
    WebhookTemplate string
    WebhookHeaders  map[string]string

    UsernameRegex        *regexp.Regexp
    DefaultUsernameRegex = `^(.+)$`

    Hostname string

    // Phase 4 additions
    IgnoreEmail      bool
    TelegramBotToken string
    TelegramChatID   string
    MaxStrikes       int
    StrikeTimeout    time.Duration

    EnablePerformanceMetrics bool
)

type Config struct {
    LogFile          string            `yaml:"LogFile"`
    BlockDuration    int               `yaml:"BlockDuration"`
    TorrentTag       string            `yaml:"TorrentTag"`
    UsernameRegex    string            `yaml:"UsernameRegex"`
    BlockMode        string            `yaml:"BlockMode"`
    BypassIPS        []string          `yaml:"BypassIPS"`
    SendWebhook      bool              `yaml:"SendWebhook"`
    WebhookURL       string            `yaml:"WebhookURL"`
    WebhookTemplate  string            `yaml:"WebhookTemplate"`
    StorageDir       string            `yaml:"StorageDir"`
    WebhookHeaders   map[string]string `yaml:"WebhookHeaders"`
    Hostname         string            `yaml:"Hostname"`
    IgnoreEmail      bool              `yaml:"IgnoreEmail"`
    TelegramBotToken string            `yaml:"TelegramBotToken"`
    TelegramChatID   string            `yaml:"TelegramChatID"`
    MaxStrikes       int               `yaml:"MaxStrikes"`
    StrikeTimeout    string            `yaml:"StrikeTimeout"`
}

func LoadConfig(configPath string) error {
    configFile, err := os.ReadFile(configPath)
    if err != nil {
        return err
    }

    var cfg Config
    err = yaml.Unmarshal(configFile, &cfg)
    if err != nil {
        return err
    }

    LogFile = cfg.LogFile
    BlockDuration = cfg.BlockDuration
    TorrentTag = cfg.TorrentTag
    SendWebhook = cfg.SendWebhook
    WebhookURL = cfg.WebhookURL
    WebhookHeaders = cfg.WebhookHeaders

    if cfg.UsernameRegex != "" {
        UsernameRegex, err = regexp.Compile(cfg.UsernameRegex)
    } else {
        UsernameRegex, err = regexp.Compile(DefaultUsernameRegex)
    }
    if err != nil {
        return fmt.Errorf("invalid UsernameRegex pattern: %v", err)
    }

    // Fixed Hostname logic: use config if provided, otherwise fallback to system hostname safely
    if cfg.Hostname != "" {
        Hostname = cfg.Hostname
    } else {
        sysHostname, err := os.Hostname()
        if err != nil {
            log.Printf("Warning: could not determine system hostname: %v. Using 'unknown'.", err)
            Hostname = "unknown"
        } else {
            Hostname = sysHostname
        }
    }

    if cfg.BlockMode != "" {
        BlockMode = cfg.BlockMode
    } else {
        BlockMode = "iptables"
    }

    if cfg.BypassIPS != nil {
        log.Println("Bypass IPS list:")
        BypassIPSet = make(map[string]struct{})
        for _, ip := range cfg.BypassIPS {
            BypassIPSet[ip] = struct{}{}
            log.Printf("- %s\n", ip)
        }
    } else {
        BypassIPSet = make(map[string]struct{})
    }

    if WebhookHeaders == nil {
        WebhookHeaders = make(map[string]string)
    }

    if cfg.WebhookTemplate != "" {
        WebhookTemplate = cfg.WebhookTemplate
    } else {
        WebhookTemplate = `{"username":"%s","ip":"%s","server":"%s","action":"%s","duration":%d,"timestamp":"%s"}`
    }

    StorageDir = cfg.StorageDir
    if StorageDir == "" {
        StorageDir = "/opt/tblocker"
    }

    // Phase 4 assignments
    IgnoreEmail = cfg.IgnoreEmail
    TelegramBotToken = cfg.TelegramBotToken
    TelegramChatID = cfg.TelegramChatID
    MaxStrikes = cfg.MaxStrikes

    // Parse StrikeTimeout string (e.g., "24h", "60m") into time.Duration
    if cfg.StrikeTimeout != "" {
        parsedDuration, err := time.ParseDuration(cfg.StrikeTimeout)
        if err != nil {
            log.Printf("Warning: invalid StrikeTimeout '%s', defaulting to 24h. Error: %v", cfg.StrikeTimeout, err)
            StrikeTimeout = 24 * time.Hour
        } else {
            StrikeTimeout = parsedDuration
        }
    } else {
        StrikeTimeout = 24 * time.Hour
    }

    return nil
}

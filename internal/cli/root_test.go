package cli

import "testing"

func TestRunNoArgsIsHelp(t *testing.T) {
	if err := Run(nil); err != nil {
		t.Fatalf("cevrixa with no args should print help and return nil, got: %v", err)
	}
}

func TestRunHelpTopic(t *testing.T) {
	topics := []string{
		"detect", "scan", "sbom", "sync", "explain", "why", "why-not",
		"snapshot", "info", "doctor", "version",
	}
	for _, topic := range topics {
		t.Run(topic, func(t *testing.T) {
			if err := Run([]string{"help", topic}); err != nil {
				t.Fatalf("help %s should return nil, got: %v", topic, err)
			}
		})
	}
}

func TestRunHelpUnknownTopic(t *testing.T) {
	if err := Run([]string{"help", "bogus"}); err == nil {
		t.Fatal("help with an unknown topic should return an error")
	}
}

func TestRunUnknownCommand(t *testing.T) {
	if err := Run([]string{"bogus"}); err == nil {
		t.Fatal("an unknown command should return an error")
	}
}

package server

import (
	"strings"

	"github.com/ashaibery/Next-Dot-Panel/internal/domain"
)

const maxServerNameLen = 128

func normalizeCreate(in *CreateInput) {
	in.Name = strings.TrimSpace(in.Name)
	in.Host = strings.TrimSpace(in.Host)
	in.Username = strings.TrimSpace(in.Username)
	if in.TargetType == "" {
		in.TargetType = domain.TargetSSH
	}
	if in.AuthMethod == "" {
		in.AuthMethod = domain.AuthKey
	}
	if in.HostKeyPolicy == "" {
		in.HostKeyPolicy = domain.HostKeyTOFU
	}
	if in.TargetType == domain.TargetSSH && in.Port == 0 {
		in.Port = 22
	}
}

func (s *Service) validateCreate(in CreateInput) error {
	if err := validateCommon(in.Name, in.TargetType, in.Host, in.Port, in.Username, in.AuthMethod, in.HostKeyPolicy, s.opts.LocalExecutionEnabled); err != nil {
		return err
	}
	if in.TargetType == domain.TargetLocal {
		return nil
	}
	switch in.AuthMethod {
	case domain.AuthKey:
		if !in.Credential.PrivateKey.IsSet() {
			return ErrNoCred
		}
	case domain.AuthPassword:
		if !in.Credential.Password.IsSet() {
			return ErrNoCred
		}
	case domain.AuthAgent:
		// Agent auth needs no stored material.
	}
	return nil
}

func (s *Service) validateUpdate(in UpdateInput) error {
	if in.Version <= 0 {
		return ErrInvalid
	}
	return validateCommon(in.Name, domain.TargetSSH, in.Host, in.Port, in.Username, in.AuthMethod, in.HostKeyPolicy, s.opts.LocalExecutionEnabled)
}

func validateCommon(name string, target domain.TargetType, host string, port int, username string, auth domain.AuthMethod, policy domain.HostKeyPolicy, localEnabled bool) error {
	if name == "" || len(name) > maxServerNameLen {
		return ErrInvalid
	}
	switch target {
	case domain.TargetLocal:
		if !localEnabled {
			return ErrInvalid
		}
		return nil
	case domain.TargetSSH:
	default:
		return ErrInvalid
	}
	if host == "" || len(host) > 255 {
		return ErrInvalid
	}
	if port < 1 || port > 65535 {
		return ErrInvalid
	}
	if username == "" || len(username) > 128 {
		return ErrInvalid
	}
	switch auth {
	case domain.AuthKey, domain.AuthPassword, domain.AuthAgent:
	default:
		return ErrInvalid
	}
	switch policy {
	case domain.HostKeyTOFU, domain.HostKeyStrict:
	default:
		return ErrInvalid
	}
	return nil
}

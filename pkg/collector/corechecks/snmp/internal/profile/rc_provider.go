// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024-present Datadog, Inc.

package profile

import (
	"encoding/json"
	"fmt"
	"github.com/DataDog/datadog-agent/comp/remote-config/rcclient"
	"github.com/DataDog/datadog-agent/pkg/networkdevice/profile/profiledefinition"
	"github.com/DataDog/datadog-agent/pkg/remoteconfig/state"
	"github.com/DataDog/datadog-agent/pkg/util/log"
	"sync"
	"time"
)

var rcSingleton *UpdatableProvider
var rcOnce sync.Once
var rcError error

func NewRCProvider(client rcclient.Component, initProfiles ProfileConfigMap) (Provider, error) {
	rcOnce.Do(func() {
		rcSingleton, rcError = buildAndSubscribeRCProvider(client)
	})
	if rcError != nil {
		return nil, rcError
	}
	if len(initProfiles) == 0 {
		return rcSingleton, nil
	}
	return &OverlayProvider{
		base:         rcSingleton,
		initProfiles: initProfiles,
	}, nil
}

func buildAndSubscribeRCProvider(rcClient rcclient.Component) (*UpdatableProvider, error) {
	// Load OOTB profiles from YAML
	defaultProfiles := getYamlDefaultProfiles()
	if defaultProfiles == nil {
		return nil, fmt.Errorf("could not find OOTB profiles")
	}
	userProfiles := make(ProfileConfigMap)

	provider := &UpdatableProvider{}
	provider.Update(userProfiles, defaultProfiles, time.Now())

	// Subscribe to the RC client
	rcClient.Subscribe(
		state.ProductNDMDeviceProfilesCustom,
		makeUpdate(provider))

	return provider, nil
}

func unpackRawConfigs(update map[string]state.RawConfig) (ProfileConfigMap, map[string]error) {
	errors := make(map[string]error)
	profiles := make(ProfileConfigMap)

	for k, v := range update {
		var def profiledefinition.DeviceProfileRcConfig
		err := json.Unmarshal(v.Config, &def)
		if err != nil {
			_ = log.Warnf("Error unmarshalling profile config %s: %v", k, err)
			errors[k] = err
			continue
		}
		profiles[k] = ProfileConfig{
			DefinitionFile: "",
			Definition:     def.Profile,
			IsUserProfile:  true,
		}
	}
	return profiles, errors
}

func makeUpdate(up *UpdatableProvider) func(map[string]state.RawConfig, func(string, state.ApplyStatus)) {
	onUpdate := func(update map[string]state.RawConfig, applyStateCallback func(string, state.ApplyStatus)) {
		userProfiles, errors := unpackRawConfigs(update)
		up.Update(userProfiles, up.defaultProfiles, time.Now())
		// Report successes/errors
		for k := range update {
			if errors[k] != nil {
				applyStateCallback(k, state.ApplyStatus{
					State: state.ApplyStateError,
					Error: errors[k].Error(),
				})
			} else {
				applyStateCallback(k, state.ApplyStatus{
					State: state.ApplyStateAcknowledged,
				})
			}
		}
	}
	return onUpdate
}

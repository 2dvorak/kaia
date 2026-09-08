// Copyright 2026 The Kaia Authors
// This file is part of the kaia library.
//
// The kaia library is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// The kaia library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with the kaia library. If not, see <http://www.gnu.org/licenses/>.

package types

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestTxInternalDataUnmarshalJSONEmptySignatures(t *testing.T) {
	types := []struct {
		name string
		gen  func() TxInternalData
	}{
		{"Legacy", genLegacyTransaction},
		{"EthereumAccessList", genAccessListTransaction},
		{"EthereumDynamicFee", genDynamicFeeTransaction},
		{"EthereumSetCode", genSetCodeTransaction},
		{"EthereumBlob", genBlobTransaction},
		{"ValueTransfer", genValueTransferTransaction},
		{"FeeDelegatedValueTransfer", genFeeDelegatedValueTransferTransaction},
	}

	malformed := map[string]interface{}{
		"empty":   []interface{}{},
		"null":    []interface{}{nil},
		"missing": nil,
	}

	for _, tt := range types {
		for sigName, sigValue := range malformed {
			t.Run(tt.name+"/"+sigName, func(t *testing.T) {
				raw, err := json.Marshal(tt.gen())
				require.NoError(t, err)

				var m map[string]interface{}
				require.NoError(t, json.Unmarshal(raw, &m))
				if sigName == "missing" {
					delete(m, "signatures")
				} else {
					m["signatures"] = sigValue
				}
				tampered, err := json.Marshal(m)
				require.NoError(t, err)

				dec := newTxInternalDataSerializer()
				require.NotPanics(t, func() {
					err = json.Unmarshal(tampered, dec)
				})
				require.ErrorIs(t, err, errEmptyTxSignatures)
			})
		}
	}
}

func TestTxInternalDataUnmarshalJSONEmptyFeePayerSignatures(t *testing.T) {
	malformed := map[string]interface{}{
		"empty":   []interface{}{},
		"null":    []interface{}{nil},
		"missing": nil,
	}

	for sigName, sigValue := range malformed {
		t.Run(sigName, func(t *testing.T) {
			raw, err := json.Marshal(genFeeDelegatedValueTransferTransaction())
			require.NoError(t, err)

			var m map[string]interface{}
			require.NoError(t, json.Unmarshal(raw, &m))
			if sigName == "missing" {
				delete(m, "feePayerSignatures")
			} else {
				m["feePayerSignatures"] = sigValue
			}
			tampered, err := json.Marshal(m)
			require.NoError(t, err)

			dec := newTxInternalDataSerializer()
			require.NotPanics(t, func() {
				err = json.Unmarshal(tampered, dec)
			})
			require.ErrorIs(t, err, errEmptyTxSignatures)
		})
	}
}

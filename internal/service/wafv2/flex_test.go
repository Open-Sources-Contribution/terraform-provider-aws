// Copyright IBM Corp. 2014, 2025
// SPDX-License-Identifier: MPL-2.0

package wafv2

import (
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	awstypes "github.com/aws/aws-sdk-go-v2/service/wafv2/types"
	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/hashicorp/terraform-provider-aws/names"
)

func Test_expandWebACLRulesJSON(t *testing.T) {
	t.Parallel()

	testCases := map[string]struct {
		rawRules string
		want     []awstypes.Rule
		wantErr  bool
	}{
		"empty string": {
			rawRules: "",
			wantErr:  true,
		},
		"empty array": {
			rawRules: "[]",
			want:     []awstypes.Rule{},
		},
		"single empty object": {
			rawRules: "[{}]",
			wantErr:  true,
		},
		"single null object": {
			rawRules: "[null]",
			wantErr:  true,
		},
		"valid object": {
			rawRules: `[{"Action":{"Count":{}},"Name":"rule-1","Priority":1,"Statement":{"RateBasedStatement":{"AggregateKeyType":"IP","EvaluationWindowSec":600,"Limit":10000,"ScopeDownStatement":{"GeoMatchStatement":{"CountryCodes":["US","NL"]}}}},"VisibilityConfig":{"CloudwatchMetricsEnabled":false,"MetricName":"friendly-rule-metric-name","SampledRequestsEnabled":false}}]`,
			want: []awstypes.Rule{
				{
					Name:     aws.String("rule-1"),
					Priority: 1,
					Action: &awstypes.RuleAction{
						Count: &awstypes.CountAction{},
					},
					Statement: &awstypes.Statement{
						RateBasedStatement: &awstypes.RateBasedStatement{
							Limit:               aws.Int64(10000),
							AggregateKeyType:    awstypes.RateBasedStatementAggregateKeyType("IP"),
							EvaluationWindowSec: 600,
							ScopeDownStatement: &awstypes.Statement{
								GeoMatchStatement: &awstypes.GeoMatchStatement{
									CountryCodes: []awstypes.CountryCode{"US", "NL"},
								},
							},
						},
					},
					VisibilityConfig: &awstypes.VisibilityConfig{
						CloudWatchMetricsEnabled: false,
						MetricName:               aws.String("friendly-rule-metric-name"),
						SampledRequestsEnabled:   false,
					},
				},
			},
		},
		"valid and empty object": {
			rawRules: `[{"Action":{"Count":{}},"Name":"rule-1","Priority":1,"Statement":{"RateBasedStatement":{"AggregateKeyType":"IP","EvaluationWindowSec":600,"Limit":10000,"ScopeDownStatement":{"GeoMatchStatement":{"CountryCodes":["US","NL"]}}}},"VisibilityConfig":{"CloudwatchMetricsEnabled":false,"MetricName":"friendly-rule-metric-name","SampledRequestsEnabled":false}},{}]`,
			wantErr:  true,
		},
		"valid object SearchString": {
			rawRules: `[{"Name" : "test_rule0","Priority":0,"Statement":{"AndStatement":{"Statements":[{"ByteMatchStatement":{"SearchString":"test","FieldToMatch":{"SingleHeader":{"Name":"host"}},"TextTransformations":[{"Priority":0,"Type":"NONE"}],"PositionalConstraint":"EXACTLY"}}]},"ByteMatchStatement":{"SearchString":"test","FieldToMatch":{"SingleHeader":{"Name":"host"}},"TextTransformations":[{"Priority":0,"Type":"NONE"}],"PositionalConstraint":"EXACTLY"}},"Action":{"Block":{}},"VisibilityConfig":{"SampledRequestsEnabled":true,"CloudWatchMetricsEnabled":true,"MetricName":"test_rule0"}}]`,
			want: []awstypes.Rule{
				{
					Name:     aws.String("test_rule0"),
					Priority: 0,
					Action: &awstypes.RuleAction{
						Block: &awstypes.BlockAction{},
					},
					VisibilityConfig: &awstypes.VisibilityConfig{
						SampledRequestsEnabled:   true,
						CloudWatchMetricsEnabled: true,
						MetricName:               aws.String("test_rule0"),
					},
					Statement: &awstypes.Statement{
						AndStatement: &awstypes.AndStatement{
							Statements: []awstypes.Statement{
								{
									ByteMatchStatement: &awstypes.ByteMatchStatement{
										SearchString: []byte("test"),
										FieldToMatch: &awstypes.FieldToMatch{
											SingleHeader: &awstypes.SingleHeader{
												Name: aws.String("host"),
											},
										},
										TextTransformations: []awstypes.TextTransformation{
											{
												Priority: 0,
												Type:     awstypes.TextTransformationType("NONE"),
											},
										},
										PositionalConstraint: awstypes.PositionalConstraint("EXACTLY"),
									},
								},
							},
						},
						ByteMatchStatement: &awstypes.ByteMatchStatement{
							SearchString: []byte("test"),
							FieldToMatch: &awstypes.FieldToMatch{
								SingleHeader: &awstypes.SingleHeader{
									Name: aws.String("host"),
								},
							},
							TextTransformations: []awstypes.TextTransformation{
								{
									Priority: 0,
									Type:     awstypes.TextTransformationType("NONE"),
								},
							},
							PositionalConstraint: awstypes.PositionalConstraint("EXACTLY"),
						},
					},
				},
			},
		},
	}

	ignoreExportedOpts := cmpopts.IgnoreUnexported(
		awstypes.Rule{},
		awstypes.RuleAction{},
		awstypes.CountAction{},
		awstypes.Statement{},
		awstypes.RateBasedStatement{},
		awstypes.GeoMatchStatement{},
		awstypes.VisibilityConfig{},
		awstypes.SingleHeader{},
		awstypes.ByteMatchStatement{},
		awstypes.FieldToMatch{},
		awstypes.TextTransformation{},
		awstypes.BlockAction{},
		awstypes.AndStatement{},
	)

	for name, tc := range testCases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			got, err := expandWebACLRulesJSON(tc.rawRules)
			if (err != nil) != tc.wantErr {
				t.Errorf("expandWebACLRulesJSON() error = %v, wantErr %v", err, tc.wantErr)
				return
			}
			if diff := cmp.Diff(got, tc.want, ignoreExportedOpts); diff != "" {
				t.Errorf("unexpected diff (+wanted, -got): %s", diff)
			}
		})
	}
}

func TestExpandStatement_RateBased_ScopeDown_Not_IPSet(t *testing.T) {
	// RateBased -> ScopeDown -> Not -> Statement -> IPSetReference

	input := map[string]any{
		"rate_based_statement": []any{
			map[string]any{
				"limit":                 1000,
				"aggregate_key_type":    "IP",
				"evaluation_window_sec": 300,
				"scope_down_statement": []any{
					map[string]any{
						"not_statement": []any{
							map[string]any{
								"statement": []any{
									map[string]any{
										"ip_set_reference_statement": []any{
											map[string]any{
												names.AttrARN: "arn:aws:wafv2:us-east-1:123456789012:regional/ipset/test/123",
											},
										},
										// Assume empty lists for others
										"byte_match_statement": []any{},
									},
								},
							},
						},
					},
				},
			},
		},
	}

	stmt := expandStatement(input)

	if stmt == nil {
		t.Fatal("Expected statement, got nil")
	}

	if stmt.RateBasedStatement == nil {
		t.Fatal("RateBasedStatement is nil")
	}

	if stmt.RateBasedStatement.ScopeDownStatement == nil {
		t.Fatal("ScopeDownStatement is nil")
	}

	if stmt.RateBasedStatement.ScopeDownStatement.NotStatement == nil {
		t.Fatal("NotStatement is nil")
	}

	if stmt.RateBasedStatement.ScopeDownStatement.NotStatement.Statement == nil {
		t.Fatal("Inner Statement is nil")
	}

	if stmt.RateBasedStatement.ScopeDownStatement.NotStatement.Statement.IPSetReferenceStatement == nil {
		t.Fatal("IPSetReferenceStatement is nil")
	}

	if aws.ToString(stmt.RateBasedStatement.ScopeDownStatement.NotStatement.Statement.IPSetReferenceStatement.ARN) != "arn:aws:wafv2:us-east-1:123456789012:regional/ipset/test/123" {
		t.Errorf("Unexpected ARN")
	}
}

func TestExpandStatement_DeepNesting(t *testing.T) {
	// Nesting level 6: Not -> Not -> Not -> Not -> Not -> Statement -> IPSet
	input := map[string]any{
		"not_statement": []any{
			map[string]any{
				"statement": []any{
					map[string]any{
						"not_statement": []any{
							map[string]any{
								"statement": []any{
									map[string]any{
										"not_statement": []any{
											map[string]any{
												"statement": []any{
													map[string]any{
														"not_statement": []any{
															map[string]any{
																"statement": []any{
																	map[string]any{
																		"not_statement": []any{
																			map[string]any{
																				"statement": []any{
																					map[string]any{
																						"ip_set_reference_statement": []any{
																							map[string]any{
																								names.AttrARN: "arn:aws:wafv2:us-east-1:123456789012:regional/ipset/test/123",
																							},
																						},
																					},
																				},
																			},
																		},
																	},
																},
															},
														},
													},
												},
											},
										},
									},
								},
							},
						},
					},
				},
			},
		},
	}

	stmt := expandStatement(input)

	if stmt == nil {
		t.Fatal("Expected statement, got nil")
	}

	// Check deepest statement
	s := stmt
	for i := 0; i < 5; i++ {
		if s.NotStatement == nil {
			t.Fatalf("Level %d NotStatement is nil", i)
		}
		if s.NotStatement.Statement == nil {
			t.Fatalf("Level %d Statement is nil", i)
		}
		s = s.NotStatement.Statement
	}

	if s.IPSetReferenceStatement == nil {
		t.Fatal("Deepest IPSetReferenceStatement is nil")
	}
}

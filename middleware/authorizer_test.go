package middleware

import (
	"fmt"
	"net/http"
	"reflect"
	"testing"

	"k8s.io/api/authentication/v1"
	authorizationv1 "k8s.io/api/authorization/v1"
	authv1 "k8s.io/client-go/kubernetes/typed/authorization/v1"
)

type fakeSubjectAccessReview struct {
	SubjectAccessReview *authorizationv1.SubjectAccessReview
}

func (fsar fakeSubjectAccessReview) Create(sar *authorizationv1.SubjectAccessReview) (*authorizationv1.SubjectAccessReview, error) {
	if !reflect.DeepEqual(fsar.SubjectAccessReview.Spec, sar.Spec) {
		return nil, fmt.Errorf("unknown subject access review")
	}
	return fsar.SubjectAccessReview, nil
}

func TestSARUserInfoAuthorizer(t *testing.T) {
	testCases := []struct {
		name             string
		sar              authv1.SubjectAccessReviewExpansion
		user             v1.UserInfo
		reqURL           string
		reqMethod        string
		expectedDecision Decision
		shouldError      bool
	}{
		{
			name: "allowed request",
			sar: fakeSubjectAccessReview{
				SubjectAccessReview: &authorizationv1.SubjectAccessReview{
					Spec: authorizationv1.SubjectAccessReviewSpec{
						User:   "foo",
						Groups: []string{},
						Extra:  nil,
						NonResourceAttributes: &authorizationv1.NonResourceAttributes{
							Path: "/testing",
							Verb: http.MethodGet,
						},
					},
					Status: authorizationv1.SubjectAccessReviewStatus{
						Allowed: true,
					},
				},
			},
			user: v1.UserInfo{
				Username: "foo",
				Groups:   []string{},
				Extra:    nil,
			},
			reqURL:           "/testing",
			reqMethod:        http.MethodGet,
			expectedDecision: DecisionAllowed,
		},
		{
			name: "no opinion request",
			sar: fakeSubjectAccessReview{
				SubjectAccessReview: &authorizationv1.SubjectAccessReview{
					Spec: authorizationv1.SubjectAccessReviewSpec{
						User:   "foo",
						Groups: []string{},
						Extra:  nil,
						NonResourceAttributes: &authorizationv1.NonResourceAttributes{
							Path: "/testing",
							Verb: http.MethodGet,
						},
					},
					Status: authorizationv1.SubjectAccessReviewStatus{},
				},
			},
			user: v1.UserInfo{
				Username: "foo",
				Groups:   []string{},
				Extra:    nil,
			},
			reqURL:           "/testing",
			reqMethod:        http.MethodGet,
			expectedDecision: DecisionNoOpinion,
		},
		{
			name: "denied request",
			sar: fakeSubjectAccessReview{
				SubjectAccessReview: &authorizationv1.SubjectAccessReview{
					Spec: authorizationv1.SubjectAccessReviewSpec{
						User:   "foo",
						Groups: []string{},
						Extra:  map[string]authorizationv1.ExtraValue{"scope": []string{"hello"}},
						NonResourceAttributes: &authorizationv1.NonResourceAttributes{
							Path: "/testing",
							Verb: http.MethodGet,
						},
					},
					Status: authorizationv1.SubjectAccessReviewStatus{
						Denied: true,
					},
				},
			},
			user: v1.UserInfo{
				Username: "foo",
				Groups:   []string{},
				Extra:    map[string]v1.ExtraValue{"scope": []string{"hello"}},
			},
			reqURL:           "/testing",
			reqMethod:        http.MethodGet,
			expectedDecision: DecisionDeny,
		},
		{
			name: "allowed and denied",
			sar: fakeSubjectAccessReview{
				SubjectAccessReview: &authorizationv1.SubjectAccessReview{
					Spec: authorizationv1.SubjectAccessReviewSpec{
						User:   "foo",
						Groups: []string{},
						Extra:  nil,
						NonResourceAttributes: &authorizationv1.NonResourceAttributes{
							Path: "/testing",
							Verb: http.MethodGet,
						},
					},
					Status: authorizationv1.SubjectAccessReviewStatus{
						Denied:  true,
						Allowed: true,
					},
				},
			},
			user: v1.UserInfo{
				Username: "foo",
				Groups:   []string{},
				Extra:    nil,
			},
			reqURL:           "/testing",
			reqMethod:        http.MethodGet,
			expectedDecision: DecisionDeny,
			shouldError:      true,
		},
		{
			name: "errored on creation",
			sar: fakeSubjectAccessReview{
				SubjectAccessReview: &authorizationv1.SubjectAccessReview{
					Spec: authorizationv1.SubjectAccessReviewSpec{
						User:   "unknown",
						Groups: []string{},
						Extra:  nil,
						NonResourceAttributes: &authorizationv1.NonResourceAttributes{
							Path: "/testing",
							Verb: http.MethodGet,
						},
					},
					Status: authorizationv1.SubjectAccessReviewStatus{
						Denied:  true,
						Allowed: true,
					},
				},
			},
			user: v1.UserInfo{
				Username: "foo",
				Groups:   []string{},
				Extra:    nil,
			},
			reqURL:           "/testing",
			reqMethod:        http.MethodGet,
			expectedDecision: DecisionDeny,
			shouldError:      true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			s := SARUserInfoAuthorizer{
				SAR: tc.sar,
			}
			request, err := http.NewRequest(tc.reqMethod, tc.reqURL, nil)
			if err != nil {
				t.Fatal()
			}
			dec, err := s.Authorize(tc.user, request)
			if err != nil {
				if tc.shouldError {
					return
				}
				t.Fatalf("unknown error occured: %v", err)
			}
			if dec != tc.expectedDecision {
				t.Fatalf("expected: %v decision got: %v", tc.expectedDecision, dec)
			}
		})
	}
}

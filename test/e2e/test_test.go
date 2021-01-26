package e2e

import (
	"context"
	"fmt"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"testing"
)

func TestTest(t *testing.T) {
	data, err := setupTest(t)
	if err != nil {
		t.Fatalf("Error when setting up test: %v", err)
	}
	defer teardownTest(t, data)
	list, err := data.crdClient.ControlplaneV1beta2().NetworkPolicies().List(context.TODO(), metav1.ListOptions{})
	if err != nil {
		t.Error(err)
	}
	for _, i := range list.Items {
		fmt.Println(i.Name)
	}
}
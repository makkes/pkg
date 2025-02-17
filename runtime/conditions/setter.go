/*
Copyright 2020 The Kubernetes Authors.
Copyright 2021 The Flux authors

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.

This file is modified from the source at
https://github.com/kubernetes-sigs/cluster-api/tree/7478817225e0a75acb6e14fc7b438231578073d2/util/conditions/setter.go,
and initially adapted to work with the `metav1.Condition` and `metav1.ConditionStatus` types.
More concretely, this includes the removal of "condition severity" related functionalities, as this is not supported by
the `metav1.Condition` type.
*/

package conditions

import (
	"fmt"
	"sort"
	"time"

	"github.com/fluxcd/pkg/apis/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// Setter is an interface that defines methods a Kubernetes object should implement in order to
// use the conditions package for setting conditions.
type Setter interface {
	Getter
	meta.ObjectWithConditionsSetter
}

// Set sets the given condition.
//
// NOTE: If a condition already exists, the LastTransitionTime is updated only if a change is detected in any of the
// following fields: Status, Reason, and Message. The ObservedGeneration is always updated.
func Set(to Setter, condition *metav1.Condition) {
	if to == nil || condition == nil {
		return
	}

	// Always set the observed generation on the condition.
	condition.ObservedGeneration = to.GetGeneration()

	// Check if the new conditions already exists, and change it only if there is a status
	// transition (otherwise we should preserve the current last transition time)-
	conditions := to.GetConditions()
	exists := false
	for i := range conditions {
		existingCondition := conditions[i]
		if existingCondition.Type == condition.Type {
			exists = true
			if !hasSameState(&existingCondition, condition) {
				condition.LastTransitionTime = metav1.NewTime(time.Now().UTC().Truncate(time.Second))
				conditions[i] = *condition
				break
			}
			condition.LastTransitionTime = existingCondition.LastTransitionTime
			break
		}
	}

	// If the condition does not exist, add it, setting the transition time only if not already set
	if !exists {
		if condition.LastTransitionTime.IsZero() {
			condition.LastTransitionTime = metav1.NewTime(time.Now().UTC().Truncate(time.Second))
		}
		conditions = append(conditions, *condition)
	}

	// Sorts conditions for convenience of the consumer, i.e. kubectl.
	sort.Slice(conditions, func(i, j int) bool {
		return lexicographicLess(&conditions[i], &conditions[j])
	})

	to.SetConditions(conditions)
}

// TrueCondition returns a condition with Status=True and the given type, reason and message.
func TrueCondition(t, reason, messageFormat string, messageArgs ...interface{}) *metav1.Condition {
	return &metav1.Condition{
		Type:    t,
		Status:  metav1.ConditionTrue,
		Reason:  reason,
		Message: fmt.Sprintf(messageFormat, messageArgs...),
	}
}

// FalseCondition returns a condition with Status=False and the given type, reason and message.
func FalseCondition(t, reason, messageFormat string, messageArgs ...interface{}) *metav1.Condition {
	return &metav1.Condition{
		Type:    t,
		Status:  metav1.ConditionFalse,
		Reason:  reason,
		Message: fmt.Sprintf(messageFormat, messageArgs...),
	}
}

// UnknownCondition returns a condition with Status=Unknown and the given type, reason and message.
func UnknownCondition(t, reason, messageFormat string, messageArgs ...interface{}) *metav1.Condition {
	return &metav1.Condition{
		Type:    t,
		Status:  metav1.ConditionUnknown,
		Reason:  reason,
		Message: fmt.Sprintf(messageFormat, messageArgs...),
	}
}

// MarkTrue sets Status=True for the condition with the given type, reason and message.
func MarkTrue(to Setter, t, reason, messageFormat string, messageArgs ...interface{}) {
	Set(to, TrueCondition(t, reason, messageFormat, messageArgs...))
}

// MarkUnknown sets Status=Unknown for the condition with the given type, reason and message.
func MarkUnknown(to Setter, t, reason, messageFormat string, messageArgs ...interface{}) {
	Set(to, UnknownCondition(t, reason, messageFormat, messageArgs...))
}

// MarkFalse sets Status=False for the condition with the given type, reason and message.
func MarkFalse(to Setter, t, reason, messageFormat string, messageArgs ...interface{}) {
	Set(to, FalseCondition(t, reason, messageFormat, messageArgs...))
}

// SetSummary creates a new summary condition with the summary of all the conditions existing on an object.
// If the object does not have other conditions, no summary condition is generated.
func SetSummary(to Setter, targetCondition string, options ...MergeOption) {
	Set(to, summary(to, targetCondition, options...))
}

// SetMirror creates a new condition by mirroring the the Ready condition from a dependent object;
// if the Ready condition does not exists in the source object, no target conditions is generated.
func SetMirror(to Setter, targetCondition string, from Getter, options ...MirrorOptions) {
	Set(to, mirror(from, targetCondition, options...))
}

// SetAggregate creates a new condition with the aggregation of all the conditions from a list of dependency objects,
// or a subset using WithConditions; if none of the source objects have a condition within the scope of the merge
// operation, no target condition is generated.
func SetAggregate(to Setter, targetCondition string, from []Getter, options ...MergeOption) {
	Set(to, aggregate(from, targetCondition, options...))
}

// Delete deletes the condition with the given type.
func Delete(to Setter, t string) {
	if to == nil {
		return
	}

	conditions := to.GetConditions()
	newConditions := make([]metav1.Condition, 0, len(conditions))
	for _, condition := range conditions {
		if condition.Type != t {
			newConditions = append(newConditions, condition)
		}
	}
	to.SetConditions(newConditions)
}

// conditionWeights defines the weight of condition types that have priority in lexicographicLess.
// TODO(hidde): given Reconciling is an abnormality-true type, and SHOULD only be present on the
//  resource if applicable, I think it actually should have a higher priority than Ready.
var conditionWeights = map[string]int{
	meta.StalledCondition:     0,
	meta.ReadyCondition:       1,
	meta.ReconcilingCondition: 2,
}

// lexicographicLess returns true if a condition is less than another with regards to the to order of conditions
// designed for convenience of the consumer, i.e. kubectl. The condition types in conditionWeights always go first,
// sorted by their defined weight, followed by all the other conditions sorted lexicographically by Type.
func lexicographicLess(i, j *metav1.Condition) bool {
	w1, ok1 := conditionWeights[i.Type]
	w2, ok2 := conditionWeights[j.Type]
	switch {
	case ok1 && ok2:
		return w1 < w2
	case ok1, ok2:
		return !ok2
	default:
		return i.Type < j.Type
	}
}

// hasSameState returns true if a condition has the same state of another; state is defined by the union of following
// fields: Type, Status, Reason, and Message (it excludes LastTransitionTime and ObservedGeneration).
func hasSameState(i, j *metav1.Condition) bool {
	return i.Type == j.Type &&
		i.Status == j.Status &&
		i.Reason == j.Reason &&
		i.Message == j.Message
}

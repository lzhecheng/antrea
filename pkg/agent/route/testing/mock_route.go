// Copyright 2021 Antrea Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//

// Code generated by MockGen. DO NOT EDIT.
// Source: antrea.io/antrea/pkg/agent/route (interfaces: Interface)

// Package testing is a generated GoMock package.
package testing

import (
	config "antrea.io/antrea/pkg/agent/config"
	gomock "github.com/golang/mock/gomock"
	net "net"
	reflect "reflect"
)

// MockInterface is a mock of Interface interface
type MockInterface struct {
	ctrl     *gomock.Controller
	recorder *MockInterfaceMockRecorder
}

// MockInterfaceMockRecorder is the mock recorder for MockInterface
type MockInterfaceMockRecorder struct {
	mock *MockInterface
}

// NewMockInterface creates a new mock instance
func NewMockInterface(ctrl *gomock.Controller) *MockInterface {
	mock := &MockInterface{ctrl: ctrl}
	mock.recorder = &MockInterfaceMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use
func (m *MockInterface) EXPECT() *MockInterfaceMockRecorder {
	return m.recorder
}

// AddRoutes mocks base method
func (m *MockInterface) AddRoutes(arg0 *net.IPNet, arg1 string, arg2, arg3 net.IP) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "AddRoutes", arg0, arg1, arg2, arg3)
	ret0, _ := ret[0].(error)
	return ret0
}

// AddRoutes indicates an expected call of AddRoutes
func (mr *MockInterfaceMockRecorder) AddRoutes(arg0, arg1, arg2, arg3 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "AddRoutes", reflect.TypeOf((*MockInterface)(nil).AddRoutes), arg0, arg1, arg2, arg3)
}

// AddSNATRule mocks base method
func (m *MockInterface) AddSNATRule(arg0 net.IP, arg1 uint32) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "AddSNATRule", arg0, arg1)
	ret0, _ := ret[0].(error)
	return ret0
}

// AddSNATRule indicates an expected call of AddSNATRule
func (mr *MockInterfaceMockRecorder) AddSNATRule(arg0, arg1 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "AddSNATRule", reflect.TypeOf((*MockInterface)(nil).AddSNATRule), arg0, arg1)
}

// AddServiceRoutes mocks base method
func (m *MockInterface) AddServiceRoutes(arg0, arg1 net.IP) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "AddServiceRoutes", arg0, arg1)
	ret0, _ := ret[0].(error)
	return ret0
}

// AddServiceRoutes indicates an expected call of AddServiceRoutes
func (mr *MockInterfaceMockRecorder) AddServiceRoutes(arg0, arg1 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "AddServiceRoutes", reflect.TypeOf((*MockInterface)(nil).AddServiceRoutes), arg0, arg1)
}

// DeleteRoutes mocks base method
func (m *MockInterface) DeleteRoutes(arg0 *net.IPNet) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "DeleteRoutes", arg0)
	ret0, _ := ret[0].(error)
	return ret0
}

// DeleteRoutes indicates an expected call of DeleteRoutes
func (mr *MockInterfaceMockRecorder) DeleteRoutes(arg0 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "DeleteRoutes", reflect.TypeOf((*MockInterface)(nil).DeleteRoutes), arg0)
}

// DeleteSNATRule mocks base method
func (m *MockInterface) DeleteSNATRule(arg0 uint32) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "DeleteSNATRule", arg0)
	ret0, _ := ret[0].(error)
	return ret0
}

// DeleteSNATRule indicates an expected call of DeleteSNATRule
func (mr *MockInterfaceMockRecorder) DeleteSNATRule(arg0 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "DeleteSNATRule", reflect.TypeOf((*MockInterface)(nil).DeleteSNATRule), arg0)
}

// DeleteServiceRoutes mocks base method
func (m *MockInterface) DeleteServiceRoutes(arg0 net.IP) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "DeleteServiceRoutes", arg0)
	ret0, _ := ret[0].(error)
	return ret0
}

// DeleteServiceRoutes indicates an expected call of DeleteServiceRoutes
func (mr *MockInterfaceMockRecorder) DeleteServiceRoutes(arg0 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "DeleteServiceRoutes", reflect.TypeOf((*MockInterface)(nil).DeleteServiceRoutes), arg0)
}

// Initialize mocks base method
func (m *MockInterface) Initialize(arg0 *config.NodeConfig, arg1 func()) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Initialize", arg0, arg1)
	ret0, _ := ret[0].(error)
	return ret0
}

// Initialize indicates an expected call of Initialize
func (mr *MockInterfaceMockRecorder) Initialize(arg0, arg1 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Initialize", reflect.TypeOf((*MockInterface)(nil).Initialize), arg0, arg1)
}

// MigrateRoutesToGw mocks base method
func (m *MockInterface) MigrateRoutesToGw(arg0 string) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "MigrateRoutesToGw", arg0)
	ret0, _ := ret[0].(error)
	return ret0
}

// MigrateRoutesToGw indicates an expected call of MigrateRoutesToGw
func (mr *MockInterfaceMockRecorder) MigrateRoutesToGw(arg0 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "MigrateRoutesToGw", reflect.TypeOf((*MockInterface)(nil).MigrateRoutesToGw), arg0)
}

// Reconcile mocks base method
func (m *MockInterface) Reconcile(arg0 []string) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Reconcile", arg0)
	ret0, _ := ret[0].(error)
	return ret0
}

// Reconcile indicates an expected call of Reconcile
func (mr *MockInterfaceMockRecorder) Reconcile(arg0 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Reconcile", reflect.TypeOf((*MockInterface)(nil).Reconcile), arg0)
}

// Run mocks base method
func (m *MockInterface) Run(arg0 <-chan struct{}) {
	m.ctrl.T.Helper()
	m.ctrl.Call(m, "Run", arg0)
}

// Run indicates an expected call of Run
func (mr *MockInterfaceMockRecorder) Run(arg0 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Run", reflect.TypeOf((*MockInterface)(nil).Run), arg0)
}

// UnMigrateRoutesFromGw mocks base method
func (m *MockInterface) UnMigrateRoutesFromGw(arg0 *net.IPNet, arg1 string) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "UnMigrateRoutesFromGw", arg0, arg1)
	ret0, _ := ret[0].(error)
	return ret0
}

// UnMigrateRoutesFromGw indicates an expected call of UnMigrateRoutesFromGw
func (mr *MockInterfaceMockRecorder) UnMigrateRoutesFromGw(arg0, arg1 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "UnMigrateRoutesFromGw", reflect.TypeOf((*MockInterface)(nil).UnMigrateRoutesFromGw), arg0, arg1)
}

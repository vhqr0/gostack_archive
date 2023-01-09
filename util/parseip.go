package util

import (
	"errors"
	"fmt"
	"net"
)

func ParseIP4(ipStr string) (net.IP, error) {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return nil, errors.New(fmt.Sprintf("invalid IP %s", ipStr))
	}
	ip = ip.To4()
	if ip == nil {
		return nil, errors.New(fmt.Sprintf("invalid IPv4 %s", ipStr))
	}
	return ip, nil
}

func ParseCIDR4(cidrStr string) (net.IP, *net.IPNet, error) {
	ip, ipnet, err := net.ParseCIDR(cidrStr)
	if err != nil {
		return nil, nil, err
	}
	if _, bits := ipnet.Mask.Size(); bits != 32 {
		return nil, nil, errors.New(fmt.Sprintf("invalid CIDR4 %s", cidrStr))
	}
	ip = ip.To4()
	if ip == nil {
		return nil, nil, errors.New(fmt.Sprintf("invalid IPv4 %s", cidrStr))
	}
	return ip, ipnet, nil
}

func ParseIP6(ipStr string) (net.IP, error) {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return nil, errors.New(fmt.Sprintf("invalid IP %s", ipStr))
	}
	ip = ip.To16()
	if ip == nil {
		return nil, errors.New(fmt.Sprintf("invalid IPv6 %s", ipStr))
	}
	return ip, nil
}

func ParseCIDR6(cidrStr string) (net.IP, *net.IPNet, error) {
	ip, ipnet, err := net.ParseCIDR(cidrStr)
	if err != nil {
		return nil, nil, err
	}
	if _, bits := ipnet.Mask.Size(); bits != 128 {
		return nil, nil, errors.New(fmt.Sprintf("invalid CIDR6 %s", cidrStr))
	}
	ip = ip.To16()
	if ip == nil {
		return nil, nil, errors.New(fmt.Sprintf("invalid IPv6 %s", cidrStr))
	}
	return ip, ipnet, nil
}

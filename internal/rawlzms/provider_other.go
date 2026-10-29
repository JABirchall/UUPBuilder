//go:build !windows

package rawlzms

import "context"

type Provider struct{}

func SystemPath() (string, error)                                     { return "", ErrProvider }
func Open(context.Context, string) (*Provider, error)                 { return nil, ErrProvider }
func (*Provider) Identity() Identity                                  { return Identity{} }
func (*Provider) Decode(context.Context, []byte, int) ([]byte, error) { return nil, ErrProvider }
func (*Provider) Close() error                                        { return nil }
func (*Provider) decodeInto(context.Context, []byte, []byte) error    { return ErrProvider }

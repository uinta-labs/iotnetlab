package pkg

import (
	"context"
	"fmt"
	"time"

	"connectrpc.com/connect"
	"github.com/godbus/dbus/v5"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/uinta-labs/iotnetlab/gen/protos/connections/firm/ware/dev"
	"github.com/uinta-labs/iotnetlab/gen/protos/connections/firm/ware/dev/devconnect"
)

type TimeServer struct {
	dbus *dbus.Conn
}

func NewTimeServer(dbus *dbus.Conn) *TimeServer {
	return &TimeServer{
		dbus: dbus,
	}
}

/*
The D-Bus API
The service exposes the following interfaces on the bus:

node /org/freedesktop/timedate1 {
  interface org.freedesktop.timedate1 {
    methods:
      SetTime(in  x usec_utc,
              in  b relative,
              in  b interactive);
      SetTimezone(in  s timezone,
                  in  b interactive);
      SetLocalRTC(in  b local_rtc,
                  in  b fix_system,
                  in  b interactive);
      SetNTP(in  b use_ntp,
             in  b interactive);
      ListTimezones(out as timezones);
    properties:
      readonly s Timezone = '...';
      readonly b LocalRTC = ...;
      @org.freedesktop.DBus.Property.EmitsChangedSignal("false")
      readonly b CanNTP = ...;
      readonly b NTP = ...;
      @org.freedesktop.DBus.Property.EmitsChangedSignal("false")
      readonly b NTPSynchronized = ...;
      @org.freedesktop.DBus.Property.EmitsChangedSignal("false")
      readonly t TimeUSec = ...;
      @org.freedesktop.DBus.Property.EmitsChangedSignal("false")
      readonly t RTCTimeUSec = ...;
  };
  interface org.freedesktop.DBus.Peer { ... };
  interface org.freedesktop.DBus.Introspectable { ... };
  interface org.freedesktop.DBus.Properties { ... };
};

Methods
Use SetTime() to change the system clock. Pass a value of microseconds since the UNIX epoch (1 Jan 1970 UTC). If relative is true, the passed usec value will be added to the current system time. If it is false, the current system time will be set to the passed usec value. If the system time is set with this method, the RTC will be updated as well.

Use SetTimezone() to set the system timezone. Pass a value like "Europe/Berlin" to set the timezone. Valid timezones are listed in /usr/share/zoneinfo/zone.tab. If the RTC is configured to be maintained in local time, it will be updated accordingly.

Use SetLocalRTC() to control whether the RTC is in local time or UTC. It is strongly recommended to maintain the RTC in UTC. However, some OSes (Windows) maintain the RTC in local time, which might make it necessary to enable this feature. Note that this might create various problems as daylight changes could be missed. If fix_system is "true", the time from the RTC is read again and the system clock is adjusted according to the new setting. If fix_system is "false", the system time is written to the RTC taking the new setting into account. Use fix_system=true in installers and livecds where the RTC is probably more reliable than the system time. Use fix_system=false in configuration UIs that are run during normal operation and where the system clock is probably more reliable than the RTC.

Use SetNTP() to control whether the system clock is synchronized with the network using systemd-timesyncd. This will enable and start or disable and stop the chosen time synchronization service.

ListTimezones() returns a list of time zones known on the local system as an array of names ("["Africa/Abidjan", "Africa/Accra", ..., "UTC"]").

Properties

Timezone: The current system timezone as a string like "Europe/Berlin".

*/

func tzNameToOffsetMinutes(tz string) (int32, error) {
	loc, err := time.LoadLocation(tz)
	if err != nil {
		fmt.Println("Error loading location:", err)
		return 0, err
	}

	// Get the current time in the specified location
	now := time.Now().In(loc)

	// Get the offset in seconds and convert it to hours and minutes
	_, offset := now.Zone()
	offsetMinutes := offset / 60

	return int32(offsetMinutes), nil
}

func (t *TimeServer) td() dbus.BusObject {
	return t.dbus.Object("org.freedesktop.timedate1", dbus.ObjectPath("/org/freedesktop/timedate1"))
}

func (t *TimeServer) GetTimezones(ctx context.Context, c *connect.Request[dev.GetTimezonesRequest]) (*connect.Response[dev.GetTimezonesResponse], error) {
	tzCall := t.td().CallWithContext(ctx, "org.freedesktop.timedate1.ListTimezones", 0)
	if tzCall.Err != nil {
		return nil, tzCall.Err
	}

	var timezonesResult []string
	err := tzCall.Store(&timezonesResult)
	if err != nil {
		return nil, err
	}

	tzs := make([]*dev.Timezone, 0, len(timezonesResult))
	for _, tz := range timezonesResult {
		offsetMinutes, err := tzNameToOffsetMinutes(tz)
		if err != nil {
			return nil, err
		}
		tzs = append(tzs, &dev.Timezone{
			Name:          tz,
			Id:            tz,
			OffsetMinutes: offsetMinutes,
		})
	}

	return &connect.Response[dev.GetTimezonesResponse]{
		Msg: &dev.GetTimezonesResponse{
			Timezones: tzs,
		},
	}, nil
}

func (t *TimeServer) SetTimezone(ctx context.Context, c *connect.Request[dev.SetTimezoneRequest]) (*connect.Response[dev.SetTimezoneResponse], error) {
	tzName := c.Msg.Timezone

	tzCall := t.td().CallWithContext(ctx, "org.freedesktop.timedate1.SetTimezone", 0, tzName, false)
	if tzCall.Err != nil {
		return nil, tzCall.Err
	}

	return &connect.Response[dev.SetTimezoneResponse]{
		Msg: &dev.SetTimezoneResponse{},
	}, nil
}

func (t *TimeServer) GetCurrentTime(ctx context.Context, c *connect.Request[dev.GetCurrentTimeRequest]) (*connect.Response[dev.GetCurrentTimeResponse], error) {
	timeUsec, err := t.td().GetProperty("org.freedesktop.timedate1.TimeUSec")
	if err != nil {
		return nil, err
	}

	currentTz, err := t.td().GetProperty("org.freedesktop.timedate1.Timezone")
	if err != nil {
		return nil, err
	}

	currentTzName := currentTz.Value().(string)
	offsetMinutes, err := tzNameToOffsetMinutes(currentTzName)
	if err != nil {
		return nil, err
	}

	currentTime := time.Unix(0, int64(timeUsec.Value().(uint64))*1000).In(time.UTC)
	currentTimePb := timestamppb.New(currentTime)

	return &connect.Response[dev.GetCurrentTimeResponse]{
		Msg: &dev.GetCurrentTimeResponse{
			Timezone: &dev.Timezone{
				Id:            currentTzName,
				Name:          currentTzName,
				OffsetMinutes: offsetMinutes,
			},
			Time: currentTimePb,
		},
	}, nil
}

func (t *TimeServer) SetCurrentTime(ctx context.Context, c *connect.Request[dev.SetCurrentTimeRequest]) (*connect.Response[dev.SetCurrentTimeResponse], error) {
	newTime := c.Msg.Time.AsTime()

	// Convert the time to microseconds since the UNIX epoch
	newTimeUsec := newTime.UnixNano() / 1000

	// Set the new time
	tCall := t.td().CallWithContext(ctx, "org.freedesktop.timedate1.SetTime", 0, newTimeUsec, false, false)
	if tCall.Err != nil {
		return nil, tCall.Err
	}

	return &connect.Response[dev.SetCurrentTimeResponse]{
		Msg: &dev.SetCurrentTimeResponse{},
	}, nil
}

var _ devconnect.TimeServiceHandler = (*TimeServer)(nil)

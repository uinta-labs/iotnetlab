package pkg

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"time"

	"github.com/godbus/dbus/v5"

	"github.com/uinta-labs/iotnetlab/gen/protos/connections/firm/ware/dev"
)

// NM_802_11_AP_SEC flags (for WpaFlags and RsnFlags)
//
//goland:noinspection GoSnakeCaseUsage
const (
	NM_802_11_AP_SEC_NONE            = 0x0000
	NM_802_11_AP_SEC_PAIR_WEP40      = 0x0001 // WEP (40-bit)
	NM_802_11_AP_SEC_PAIR_WEP104     = 0x0002 // WEP (104-bit)
	NM_802_11_AP_SEC_PAIR_TKIP       = 0x0004 // TKIP encryption
	NM_802_11_AP_SEC_PAIR_CCMP       = 0x0008 // CCMP encryption
	NM_802_11_AP_SEC_GROUP_WEP40     = 0x0010 // WEP (40-bit)
	NM_802_11_AP_SEC_GROUP_WEP104    = 0x0020 // WEP (104-bit)
	NM_802_11_AP_SEC_GROUP_TKIP      = 0x0040 // Group TKIP
	NM_802_11_AP_SEC_GROUP_CCMP      = 0x0080 // Group CCMP
	NM_802_11_AP_SEC_KEY_MGMT_PSK    = 0x0100 // Pre-shared key
	NM_802_11_AP_SEC_KEY_MGMT_802_1X = 0x0200 // 802.1X
)

func determineSecurity(wpaFlags, rsnFlags uint32) dev.WiFiSecurityType {
	if wpaFlags == NM_802_11_AP_SEC_NONE && rsnFlags == NM_802_11_AP_SEC_NONE {
		return dev.WiFiSecurityType_WIFI_SECURITY_OPEN
	}

	// Check for WEP
	if wpaFlags&(NM_802_11_AP_SEC_PAIR_WEP40|NM_802_11_AP_SEC_PAIR_WEP104|NM_802_11_AP_SEC_GROUP_WEP40|NM_802_11_AP_SEC_GROUP_WEP104) != 0 {
		return dev.WiFiSecurityType_WIFI_SECURITY_WEP
	}

	// Check for WPA3 Enterprise
	if rsnFlags&(NM_802_11_AP_SEC_KEY_MGMT_802_1X) != 0 && rsnFlags&(NM_802_11_AP_SEC_PAIR_CCMP|NM_802_11_AP_SEC_GROUP_CCMP) != 0 {
		return dev.WiFiSecurityType_WIFI_SECURITY_WPA3_EAP
	}

	// Check for WPA3 Personal
	if rsnFlags&(NM_802_11_AP_SEC_KEY_MGMT_PSK) != 0 && rsnFlags&(NM_802_11_AP_SEC_PAIR_CCMP|NM_802_11_AP_SEC_GROUP_CCMP) != 0 {
		return dev.WiFiSecurityType_WIFI_SECURITY_WPA3_PSK
	}

	// Check for WPA2 Enterprise
	if rsnFlags&(NM_802_11_AP_SEC_KEY_MGMT_802_1X) != 0 {
		return dev.WiFiSecurityType_WIFI_SECURITY_WPA2_EAP
	}

	// Check for WPA2 Personal
	if rsnFlags&(NM_802_11_AP_SEC_KEY_MGMT_PSK) != 0 {
		return dev.WiFiSecurityType_WIFI_SECURITY_WPA2_PSK
	}

	// Check for WPA Enterprise
	if wpaFlags&(NM_802_11_AP_SEC_KEY_MGMT_802_1X) != 0 {
		return dev.WiFiSecurityType_WIFI_SECURITY_WPA_EAP
	}

	// Check for WPA Personal
	if wpaFlags&(NM_802_11_AP_SEC_KEY_MGMT_PSK) != 0 {
		return dev.WiFiSecurityType_WIFI_SECURITY_WPA_PSK
	}

	return dev.WiFiSecurityType_WIFI_SECURITY_UNKNOWN
}

func frequencyToChannel(freq int32) int32 {
	type freqRange struct {
		low  int32
		high int32
	}

	// https://en.wikipedia.org/wiki/List_of_WLAN_channels
	var freqRangeToChannel = map[freqRange]int32{
		// 2.4 GHz
		{2401, 2423}: 1,
		{2406, 2428}: 2,
		{2411, 2433}: 3,
		{2416, 2438}: 4,
		{2421, 2443}: 5,
		{2426, 2448}: 6,
		{2431, 2453}: 7,
		{2436, 2458}: 8,
		{2441, 2463}: 9,
		{2446, 2468}: 10,
		{2451, 2473}: 11,
		{2456, 2478}: 12,
		{2461, 2483}: 13,
		{2473, 2495}: 14,

		// 5 GHz
		{5150, 5170}: 32,
		{5170, 5190}: 36,
		{5190, 5210}: 40,
		{5210, 5230}: 44,
		{5230, 5250}: 48,
		{5250, 5270}: 52,
		{5270, 5290}: 56,
		{5290, 5310}: 60,
		{5310, 5330}: 64,
		{5330, 5350}: 68,
		{5350, 5370}: 72,
		{5370, 5390}: 76,
		{5390, 5410}: 80,
		{5410, 5430}: 84,
		{5430, 5450}: 88,
		{5450, 5470}: 92,
		{5470, 5490}: 96,
		{5490, 5510}: 100,
		{5510, 5530}: 104,
		{5530, 5550}: 108,
		{5550, 5570}: 112,
		{5570, 5590}: 116,
		{5590, 5610}: 120,
		{5610, 5630}: 124,
		{5630, 5650}: 128,
		{5650, 5670}: 132,
		{5670, 5690}: 136,
		{5690, 5710}: 140,
		{5710, 5730}: 144,
		{5735, 5755}: 149,
		{5755, 5775}: 153,
		{5775, 5795}: 157,
		{5795, 5815}: 161,
		{5815, 5835}: 165,
		{5835, 5855}: 169,
		{5855, 5875}: 173,
		{5875, 5895}: 177,

		// 6 GHz
		{5925, 5945}: 2,
		{5945, 5965}: 1,
		{5965, 5985}: 5,
		{5985, 6005}: 9,
		{6005, 6025}: 13,
		{6025, 6045}: 17,
		{6045, 6065}: 21,
		{6065, 6085}: 25,
		{6085, 6105}: 29,
		{6105, 6125}: 33,
		{6125, 6145}: 37,
		{6145, 6165}: 41,
		{6165, 6185}: 45,
		{6185, 6205}: 49,
		{6205, 6225}: 53,
		{6225, 6245}: 57,
		{6245, 6265}: 61,
		{6265, 6285}: 65,
		{6285, 6305}: 69,
		{6305, 6325}: 73,
		{6325, 6345}: 77,
		{6345, 6365}: 81,
		{6365, 6385}: 85,
		{6385, 6405}: 89,
		{6405, 6425}: 93,
		{6425, 6445}: 97,
		{6445, 6465}: 101,
		{6465, 6485}: 105,
		{6485, 6505}: 109,
		{6505, 6525}: 113,
		{6525, 6545}: 117,
		{6545, 6565}: 121,
		{6565, 6585}: 125,
		{6585, 6605}: 129,
		{6605, 6625}: 133,
		{6625, 6645}: 137,
		{6645, 6665}: 141,
		{6665, 6685}: 145,
		{6685, 6705}: 149,
		{6705, 6725}: 153,
		{6725, 6745}: 157,
		{6745, 6765}: 161,
		{6765, 6785}: 165,
		{6785, 6805}: 169,
		{6805, 6825}: 173,
		{6825, 6845}: 177,
		{6845, 6865}: 181,
		{6865, 6885}: 185,
		{6885, 6905}: 189,
		{6905, 6925}: 193,
		{6925, 6945}: 197,
		{6945, 6965}: 201,
		{6965, 6985}: 205,
		{6985, 7005}: 209,
		{7005, 7025}: 213,
		{7025, 7045}: 217,
		{7045, 7065}: 221,
		{7065, 7085}: 225,
		{7085, 7105}: 229,
		{7105, 7125}: 233,
	}

	for r, c := range freqRangeToChannel {
		if freq >= r.low && freq <= r.high {
			return c
		}
	}

	return 0
}

func rssiToRating(rssi int32) dev.WiFiSignalRating {
	if rssi >= -50 {
		return dev.WiFiSignalRating_WIFI_SIGNAL_STRENGTH_EXCELLENT
	} else if rssi >= -60 {
		return dev.WiFiSignalRating_WIFI_SIGNAL_STRENGTH_GOOD
	} else if rssi >= -70 {
		return dev.WiFiSignalRating_WIFI_SIGNAL_STRENGTH_FAIR
	} else if rssi >= -80 {
		return dev.WiFiSignalRating_WIFI_SIGNAL_STRENGTH_POOR
	}
	return dev.WiFiSignalRating_WIFI_SIGNAL_STRENGTH_NONE
}

func WifiScan(ctx context.Context, conn *dbus.Conn, networkInterfaceName string) ([]*dev.WiFiAccessPoint, error) {
	accessPoints := []*dev.WiFiAccessPoint{}

	// The object path for NetworkManager
	nmPath := dbus.ObjectPath("/org/freedesktop/NetworkManager")
	nm := conn.Object("org.freedesktop.NetworkManager", nmPath)

	// Get all devices
	devices, err := nm.GetProperty("org.freedesktop.NetworkManager.AllDevices")
	if err != nil {
		log.Fatalf("Failed to get devices: %v", err)
	}

	for _, d := range devices.Value().([]dbus.ObjectPath) {
		device := conn.Object("org.freedesktop.NetworkManager", d)
		deviceType, err := device.GetProperty("org.freedesktop.NetworkManager.Device.DeviceType")
		if err != nil {
			continue // Skip on error
		}

		deviceInterfaceName, err := device.GetProperty("org.freedesktop.NetworkManager.Device.Interface")
		if err != nil {
			continue // Skip on error
		}

		if networkInterfaceName != "" {
			if deviceInterfaceName.Value().(string) != networkInterfaceName {
				continue
			}
		}

		// Check if the device is a WiFi device (type 2)
		if deviceType.Value().(uint32) == 2 {
			// initiate a scan
			// RequestScan expects “(a{sv})”?
			scan := device.Call("org.freedesktop.NetworkManager.Device.Wireless.RequestScan", 0, map[string]dbus.Variant{})
			if scan.Err != nil {
				log.Printf("Failed to initiate scan: %v", scan.Err)
				continue
			}

			wireless := conn.Object("org.freedesktop.NetworkManager", d)
			call := wireless.Call("org.freedesktop.NetworkManager.Device.Wireless.GetAccessPoints", 0)
			if call.Err != nil {
				log.Printf("Failed to get access points: %v", call.Err)
				continue
			}

			var aps []dbus.ObjectPath
			if err := call.Store(&aps); err != nil {
				log.Printf("Failed to store access points: %v", err)
				continue
			}

			//var networks []WiFiNetwork
			for _, ap := range aps {
				accessPoint := conn.Object("org.freedesktop.NetworkManager", ap)
				ssid, _ := accessPoint.GetProperty("org.freedesktop.NetworkManager.AccessPoint.Ssid")
				bsid, _ := accessPoint.GetProperty("org.freedesktop.NetworkManager.AccessPoint.HwAddress")
				frequency, _ := accessPoint.GetProperty("org.freedesktop.NetworkManager.AccessPoint.Frequency")
				strength, _ := accessPoint.GetProperty("org.freedesktop.NetworkManager.AccessPoint.Strength")
				ssidStr := string(ssid.Value().([]byte)) // Convert []byte to string

				wpaFlags, _ := accessPoint.GetProperty("org.freedesktop.NetworkManager.AccessPoint.WpaFlags")
				rsnFlags, _ := accessPoint.GetProperty("org.freedesktop.NetworkManager.AccessPoint.RsnFlags")

				protoSecurityType := determineSecurity(wpaFlags.Value().(uint32), rsnFlags.Value().(uint32))

				accessPoints = append(accessPoints, &dev.WiFiAccessPoint{
					SSID:         ssidStr,
					BSSID:        bsid.Value().(string),
					RSSI:         int32(strength.Value().(uint8)),
					Frequency:    int32(frequency.Value().(uint32)),
					Channel:      frequencyToChannel(int32(frequency.Value().(uint32))),
					SignalRating: rssiToRating(int32(strength.Value().(uint8))),
					SecurityType: protoSecurityType,
					EapConfig:    nil,
				})
			}
		}
	}

	return accessPoints, nil
}

func ConnectWiFi(ctx context.Context, conn *dbus.Conn, request *dev.WiFiConnectRequest) error {
	nmPath := dbus.ObjectPath("/org/freedesktop/NetworkManager")
	nm := conn.Object("org.freedesktop.NetworkManager", nmPath)

	// Create a new WiFi connection
	connection := map[string]map[string]dbus.Variant{
		"802-11-wireless": {
			"ssid": dbus.MakeVariant([]byte(request.SSID)),
			"mode": dbus.MakeVariant("infrastructure"),
		},
		"connection": {
			"type": dbus.MakeVariant("802-11-wireless"),
			"id":   dbus.MakeVariant(request.SSID),
		},
	}

	// Determine the security type based on provided credentials
	switch request.GetSecret().(type) {
	case *dev.WiFiConnectRequest_IsOpen:
		if !request.GetSecret().(*dev.WiFiConnectRequest_IsOpen).IsOpen {
			return errors.New("secret oneOf 'IsOpen' must be true, as any other condition must be specified instead")
		}
		fmt.Println("Connecting to open network")
		connection["802-11-wireless-security"] = map[string]dbus.Variant{
			"key-mgmt": dbus.MakeVariant("none"),
		}
		break
	case *dev.WiFiConnectRequest_Password:
		fmt.Println("Connecting to WPA/WPA2 Personal network")
		connection["802-11-wireless-security"] = map[string]dbus.Variant{
			"key-mgmt": dbus.MakeVariant("wpa-psk"),
			"psk":      dbus.MakeVariant(request.GetSecret().(*dev.WiFiConnectRequest_Password).Password),
		}
		break
	case *dev.WiFiConnectRequest_EapConfig:
		eapConfig := request.GetSecret().(*dev.WiFiConnectRequest_EapConfig).EapConfig
		// WPA/WPA2 Enterprise
		fmt.Println("Connecting to WPA/WPA2 Enterprise network")
		connection["802-11-wireless-security"] = map[string]dbus.Variant{
			"key-mgmt": dbus.MakeVariant("wpa-eap"),
		}
		connection["802-1x"] = map[string]dbus.Variant{
			"eap":      dbus.MakeVariant([]string{"tls", "peap", "ttls"}),
			"identity": dbus.MakeVariant(eapConfig.Identity),
			"password": dbus.MakeVariant(eapConfig.Password),
		}
		if eapConfig.ClientCertificate != "" {
			connection["802-1x"]["client-cert"] = dbus.MakeVariant(eapConfig.ClientCertificate)
		}
		if eapConfig.CaCertificate != "" {
			connection["802-1x"]["ca-cert"] = dbus.MakeVariant(eapConfig.CaCertificate)
		}

		break
	}

	path := dbus.ObjectPath("/org/freedesktop/NetworkManager/Settings")
	settings := conn.Object("org.freedesktop.NetworkManager", path)

	// Add the new connection to NetworkManager
	call := settings.Call("org.freedesktop.NetworkManager.Settings.AddConnection", 0, connection)
	if call.Err != nil {
		return fmt.Errorf("failed to add connection: %v", call.Err)
	}

	// Retrieve the connection path
	var newConnPath dbus.ObjectPath
	if err := call.Store(&newConnPath); err != nil {
		return fmt.Errorf("failed to store new connection path: %v", err)
	}

	// Activate the connection
	devices, err := nm.GetProperty("org.freedesktop.NetworkManager.AllDevices")
	if err != nil {
		return fmt.Errorf("failed to get devices: %v", err)
	}

	var wifiDevice dbus.ObjectPath
	for _, d := range devices.Value().([]dbus.ObjectPath) {
		device := conn.Object("org.freedesktop.NetworkManager", d)
		deviceType, err := device.GetProperty("org.freedesktop.NetworkManager.Device.DeviceType")
		if err != nil {
			continue // Skip on error
		}

		// Check if the device is a WiFi device (type 2)
		if deviceType.Value().(uint32) == 2 {
			wifiDevice = d
			break
		}
	}

	if wifiDevice == "" {
		return fmt.Errorf("no WiFi device found")
	}

	activeConnPath := nm.Call("org.freedesktop.NetworkManager.ActivateConnection", 0, newConnPath, wifiDevice, dbus.ObjectPath("/"))
	if activeConnPath.Err != nil {
		return fmt.Errorf("failed to activate connection: %v", activeConnPath.Err)
	}

	// Monitor connection status
	return monitorConnectStatus(ctx, conn)
}

func monitorConnectStatus(ctx context.Context, conn *dbus.Conn) error {
	sigChan := make(chan *dbus.Signal, 10)
	conn.Signal(sigChan)

	for {
		select {
		case sig := <-sigChan:
			if sig.Name == "org.freedesktop.NetworkManager.Connection.Active.StateChanged" {
				state := sig.Body[0].(uint32)
				switch state {
				case 2:
					fmt.Println("Connection activated")
					return nil
				case 3:
					fmt.Println("Connection deactivated")
					return fmt.Errorf("connection deactivated")
				default:
					fmt.Printf("unknown/unhandled NetworkManager.Connection.Active.StateChanged: %d\n", state)
				}
			}
		case <-time.After(30 * time.Second):
			return fmt.Errorf("connection timeout")
		}
	}
}

const (
	serviceName     = "org.freedesktop.NetworkManager"
	settings        = "org.freedesktop.NetworkManager.Settings"
	settingsObjPath = "/org/freedesktop/NetworkManager/Settings"
)

var addrData = []map[string]interface{}{
	{
		"address": "172.24.1.1",
		"prefix":  uint32(24),
	},
}

var ipv4Data = map[string]dbus.Variant{
	"method":       dbus.MakeVariant("shared"),
	"address-data": dbus.MakeVariant(addrData),
	"gateway":      dbus.MakeVariant("172.24.1.1"),
}

var ipv6Data = map[string]dbus.Variant{
	"method": dbus.MakeVariant("ignore"),
}

func nmSettingsConn(conn *dbus.Conn) dbus.BusObject {
	nmSettingsPath := dbus.ObjectPath(settingsObjPath)
	return conn.Object(serviceName, nmSettingsPath)
}

func nmConn(conn *dbus.Conn) dbus.BusObject {
	return conn.Object(serviceName, "/org/freedesktop/NetworkManager")
}

func StartHotspot(ctx context.Context, conn *dbus.Conn, hotspotSSID string, hotspotPassword string, hotspotInterfaceName string) error {
	nmSettings := nmSettingsConn(conn)

	// Check if a hotspot already exists and remove it
	connectionsCall := nmSettings.Call("org.freedesktop.NetworkManager.Settings.ListConnections", 0)
	if connectionsCall.Err != nil {
		return fmt.Errorf("failed to list connections: %v", connectionsCall.Err)
	}

	connections := []dbus.ObjectPath{}
	if err := connectionsCall.Store(&connections); err != nil {
		return fmt.Errorf("failed to read connections: %v", err)
	}

	for _, c := range connections {
		busObj := conn.Object(serviceName, c)
		log.Printf("Checking connection: %s", c)

		settingsCall := busObj.Call("org.freedesktop.NetworkManager.Settings.Connection.GetSettings", 0)
		if settingsCall.Err != nil {
			log.Fatalf("Failed to get connection settings: %v", settingsCall.Err)
		}

		settingsInfo := map[string]map[string]dbus.Variant{}
		if err := settingsCall.Store(&settingsInfo); err != nil {
			log.Fatalf("Failed to store connection settings: %v", err)
		}

		ssidBytes, ok := settingsInfo["802-11-wireless"]["ssid"].Value().([]byte)
		if !ok {
			log.Printf("Failed to get SSID bytes for connection: %s\n", c)
			continue
		}
		ssid := string(ssidBytes)

		// print as json
		b, err := json.Marshal(settingsInfo)
		if err != nil {
			log.Fatalf("Failed to marshal connection settings: %v", err)
		}
		log.Printf("Connection(%s) settings %s\n", ssid, string(b))

		if ssid == hotspotSSID {
			log.Printf("Deleting existing connection: %s", c)
			if err := busObj.Call("org.freedesktop.NetworkManager.Settings.Connection.Delete", 0).Err; err != nil {
				return fmt.Errorf("failed to delete existing connection: %v", err)
			}
		}
	}

	connectionParams := map[string]dbus.Variant{
		"type":                 dbus.MakeVariant("802-11-wireless"),
		"id":                   dbus.MakeVariant(hotspotSSID),
		"autoconnect":          dbus.MakeVariant(false),
		"autoconnect-priority": dbus.MakeVariant(0),
	}
	if hotspotInterfaceName != "" {
		connectionParams["interface-name"] = dbus.MakeVariant(hotspotInterfaceName)
	}

	wirelessSecurity := map[string]dbus.Variant{
		"key-mgmt": dbus.MakeVariant("wpa-psk"),
		"psk":      dbus.MakeVariant(hotspotPassword),
	}

	// PMF (Protected Management Frames) causes issues with some cards, but disabling seems to cause the connection
	// to fall back to TKIP
	wirelessSecurity["pmf"] = dbus.MakeVariant(1) // disable
	// So restrict to CCMP (AES) only to avoid security warnings (well, really, avoid security issues)
	wirelessSecurity["pairwise"] = dbus.MakeVariant([]string{"ccmp"})

	// Create a new hotspot connection
	hotspotConfig := map[string]map[string]dbus.Variant{
		"connection": connectionParams,
		"802-11-wireless": {
			"ssid":   dbus.MakeVariant([]byte(hotspotSSID)),
			"mode":   dbus.MakeVariant("ap"),
			"band":   dbus.MakeVariant("bg"),
			"hidden": dbus.MakeVariant(false),
		},
		"802-11-wireless-security": wirelessSecurity,
		"ipv4":                     ipv4Data,
		"ipv6":                     ipv6Data,
	}

	// Add the new connection to NetworkManager
	call := nmSettings.Call("org.freedesktop.NetworkManager.Settings.AddConnection", 0, hotspotConfig)
	if call.Err != nil {
		return fmt.Errorf("failed to add connection: %v", call.Err)
	}

	// Retrieve the connection path
	var newConnPath dbus.ObjectPath
	if err := call.Store(&newConnPath); err != nil {
		return fmt.Errorf("failed to store new connection path: %v", err)
	}

	nm := nmConn(conn)

	// Get all devices
	devices, err := nm.GetProperty("org.freedesktop.NetworkManager.AllDevices")
	if err != nil {
		return fmt.Errorf("failed to get devices: %v", err)
	}

	var wifiDevice dbus.ObjectPath
	for _, d := range devices.Value().([]dbus.ObjectPath) {
		device := conn.Object("org.freedesktop.NetworkManager", d)
		deviceType, err := device.GetProperty("org.freedesktop.NetworkManager.Device.DeviceType")
		if err != nil {
			continue // Skip on error
		}

		deviceInterfaceName, err := device.GetProperty("org.freedesktop.NetworkManager.Device.Interface")
		if err != nil {
			continue // Skip on error
		}

		if hotspotInterfaceName != "" {
			if deviceInterfaceName.Value().(string) != hotspotInterfaceName {
				continue
			}

			log.Printf("Using specified interface: %s", hotspotInterfaceName)
			wifiDevice = d
			break
		}

		// Check if the device is a WiFi device (type 2)
		if deviceType.Value().(uint32) == 2 {
			log.Printf("Found WiFi device: %s", d)
			wifiDevice = d
			break
		}
	}

	if wifiDevice == "" {
		return fmt.Errorf("no WiFi device found")
	}

	// If device has active connection, deactivate it
	activeConnections, err := nm.GetProperty("org.freedesktop.NetworkManager.ActiveConnections")
	if err != nil {
		return fmt.Errorf("failed to get active connections: %v", err)
	}

	for _, c := range activeConnections.Value().([]dbus.ObjectPath) {
		activeConn := conn.Object("org.freedesktop.NetworkManager", c)
		device, err := activeConn.GetProperty("org.freedesktop.NetworkManager.Connection.Active.Devices")
		if err != nil {
			continue
		}

		if len(device.Value().([]dbus.ObjectPath)) > 0 {
			for _, d := range device.Value().([]dbus.ObjectPath) {
				if d == wifiDevice {
					log.Printf("Deactivating active connection: %s", c)
					activeConn.Call("org.freedesktop.NetworkManager.Connection.Active.Deactivate", 0)
					break
				}
			}
		}
	}

	connActivated := make(chan struct{})
	go func() {
		// Monitor connection status
		if err = conn.AddMatchSignal(
			dbus.WithMatchInterface("org.freedesktop.NetworkManager.Connection.Active"),
		); err != nil {
			panic(err)
		}

		err := monitorHotspotStart(ctx, conn, newConnPath)
		if err != nil {
			log.Printf("Failed to activate hotspot: %v", err)
		}
		close(connActivated)
	}()

	// Activate the connection
	log.Printf("Activating connection: %s", newConnPath)
	activeConnPath := nm.Call("org.freedesktop.NetworkManager.ActivateConnection", 0, newConnPath, wifiDevice, dbus.ObjectPath("/"))
	if activeConnPath.Err != nil {
		return fmt.Errorf("failed to activate connection: %v", activeConnPath.Err)
	}

	<-connActivated

	return nil
}

func monitorHotspotStart(ctx context.Context, conn *dbus.Conn, connPath dbus.ObjectPath) error {
	sigChan := make(chan *dbus.Signal, 10)
	conn.Signal(sigChan)

	for {
		select {
		case sig := <-sigChan:
			if sig.Name == "org.freedesktop.NetworkManager.Connection.Active.StateChanged" {
				/*
					https://github.com/NetworkManager/NetworkManager/blob/99f22526ec6370646b8a54d74b2436e4590abc14/introspection/org.freedesktop.NetworkManager.Device.xml#L400C1-L404C14
					   <signal name="StateChanged">
					     <arg name="new_state" type="u"/>
					     <arg name="old_state" type="u"/>
					     <arg name="reason" type="u"/>
					   </signal>
				*/
				state := sig.Body[0].(uint32)
				switch state {
				case 2:

					// sig.Path will be an '/ActiveConnection/<n>' while connPath is '/Settings/<n>', so we'll ask the 'ActiveConnection' for the 'org.freedesktop.NetworkManager.Connection.Active.Connection' property
					perhapsConn := conn.Object("org.freedesktop.NetworkManager", sig.Path)
					connProp, err := perhapsConn.GetProperty("org.freedesktop.NetworkManager.Connection.Active.Connection")
					if err != nil {
						log.Printf("Failed to get connection path: %v", err)
						continue
					}

					if connProp.Value() != connPath {
						log.Printf("Unexpected connection path: %s (expected: %s)", connProp.Value(), connPath)
						continue
					}

					fmt.Println("Hotspot activated")

					return nil
				case 3:
					fmt.Println("Hotspot deactivated")
					// keep waiting for activation (might be deactivating an existing connection)
					continue
				}
			} else {
				log.Printf("Unhandled signal: %s // %s // %s", sig.Name, sig.Path, sig.Sender)
			}
		case <-time.After(30 * time.Second):
			return fmt.Errorf("hotspot activation timeout")
		}
	}
}

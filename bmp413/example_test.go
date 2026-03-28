package bmp413

import (
	"fmt"
	"testing"
)

func TestGenerateHeader(t *testing.T) {
	device := DeviceProfile{
		Model:             "Pixel 7a",
		Manufacturer:      "Google",
		Brand:             "google",
		Device:            "lynx",
		Product:           "lynx",
		Board:             "lynx",
		Hardware:          "lynx",
		Bootloader:        "lynx-14.5-11677884",
		Fingerprint:       "google/lynx/lynx:14/AP2A.240605.024/11860263:user/release-keys",
		BuildID:           "AP2A.240605.024",
		BuildDisplay:      "AP2A.240605.024",
		BuildTags:         "release-keys",
		BuildType:         "user",
		BuildUser:         "android-build",
		Incremental:       "11860263",
		Codename:          "REL",
		Release:           "14",
		SDKInt:            34,
		SecurityPatch:     "2024-06-05",
		PreviewSDKInt:     0,
		BaseOS:            "",
		ABI32:             "-1",
		ABI64:             "-1",
		ScreenHeight:      2219,
		ScreenWidth:       1080,
		ScreenCount:       1,
		DensityDPI:        "dpi",
		RefreshRate:       1.0,
		Host:              "r-82b05a39f2cf359a-vz7j",
		Serial:            "unknown",
		RadioVersion:      "",
		BuildTime:         1716016055000,
		UserAgent:         `Mozilla/5.0 (Linux; Android 14; Pixel 7a Build/AP2A.240605.024; wv) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/122.0.6225.0 Mobile Safari/537.36`,
		UAHash:            "ff75efd4432af9b9007656ed9eb018ebad2b2fd60908ea11e1fc81a2692d939d",
		LocaleLanguage:    "en",
		LocaleCountry:     "US",
		TimezoneOffset:    -300,
		BluetoothName:     "-1",
		TelephonyStatus:   -1,
		SIMStatus:         -1,
		NFCEnabled:        1,
		AirplaneMode:      0,
		IsTablet:          0,
		MemoryTotalKB:     23599,
		StorageTotalBytes: 887294262706,
		AppSignatureSHA1:  "a5b450c500291c28be5904d40d745bcb192b9aa7",
		WebviewFPHash:     "c8735900e74266b84eb21a3bd9ea065e3993e8364baebc69903013666cce52d5",
		SensorRates: SensorRates{
			AccelUS:    72000,
			GyroUS:     51000,
			AccelRange: 128,
			GyroRange:  128,
		},
		AndroidID: "ac431266fa088989",
		DeviceID:  "ac431266fa088989",
	}

	gen, err := NewGenerator(device, "com.iberia.android", "14.81.0", 448100, "https://ibisservices.iberia.com")
	if err != nil {
		t.Fatal(err)
	}

	header := gen.Generate(GenerateOpts{
		ServerSignal: `AAQAAAAF%2f%2f%2f%2f%2f1H5+nHUldOJ8IRPWNHIbDFyX31RC8R0BZhDbvavgNrzAQyaD78v5o2YFnPx9O3OpOpd%2fGMOarY1pV0GT48rfRlSOsk+p0LGBkMTAyWAOElnn2zjiu9I2QK36houPouOpMeBLOqSSEx1vq9C1Xq8EdeXWBuz8lcsu6uu1d%2fzqHneCyPWeQ+YbWOXz2BjeqFepcqW2ptZ4sS2XFXOGHX174M1tbtlYofXhbrdmVzJDRS4JNIPco6pcrtPh28xRO7H8%2fglIgkP2DuWbJEU3kc0xhfjEow0qJPLLx3vMWqr`,
		CPRSignal:    "1774588528637|-434560476|",
		CPRToken:     `E319E30EBB0BEF63E12DD07EAFDE3B703591548C687FE4AA7F7C0C64143C07F9~plN/2ItxKqzyk6StfRiYQamagpihX25/+ffuZQWZ+/M1D6u66xw1uNu0FMqDO3hXQPcoCmOJcXM2reOoy7xeP/f4d4yeUPDpJsAdnaTsS4bZ8xLG9Cqg3akVdQe+v7GKMGbtdDvwUimeoLNuhefLPoBCUddsNfezZqNKPfVUl6j1pImEocOf0WCHd9BRh67uIV85EgMDMDttXMu9APEdspX/8xnEApNtbgaPjdv8x/F8laliP4W53q6LIYUZgPhLEptVpJsDHNcI6n71ct2iGR3lgfzlbl+Jdu6jRg/qqhRhKfSdNcbFoXuaX81+SZ8ujPGZvQFVoxPuAxWHYcbUcbhzg5UXqN5aeLtiMcY/91NWI0soWZ2JmjRbH6mugulvMv`,
	})

	fmt.Println(header)
}

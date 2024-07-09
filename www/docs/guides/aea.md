---
description: Working with Apple's NEW AEA format.
---

# AEA

## How to extract/mount these NEW `.dmg.aea` files

- It all works seemlessly in the background so you don't have to worry about it at all. 
- It will also work offline as the `latest` version of `ipsw` will always have the AEA private keys embedded.

## What if I **want** to mess with them?

### Download AEA PEMs from remote IPSWs

![image](https://private-user-images.githubusercontent.com/6118188/338740008-3159e2ab-c0cb-47a1-ba85-d28fa9ef9007.png?jwt=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJnaXRodWIuY29tIiwiYXVkIjoicmF3LmdpdGh1YnVzZXJjb250ZW50LmNvbSIsImtleSI6ImtleTUiLCJleHAiOjE3MjA0OTkzNzEsIm5iZiI6MTcyMDQ5OTA3MSwicGF0aCI6Ii82MTE4MTg4LzMzODc0MDAwOC0zMTU5ZTJhYi1jMGNiLTQ3YTEtYmE4NS1kMjhmYTllZjkwMDcucG5nP1gtQW16LUFsZ29yaXRobT1BV1M0LUhNQUMtU0hBMjU2JlgtQW16LUNyZWRlbnRpYWw9QUtJQVZDT0RZTFNBNTNQUUs0WkElMkYyMDI0MDcwOSUyRnVzLWVhc3QtMSUyRnMzJTJGYXdzNF9yZXF1ZXN0JlgtQW16LURhdGU9MjAyNDA3MDlUMDQyNDMxWiZYLUFtei1FeHBpcmVzPTMwMCZYLUFtei1TaWduYXR1cmU9NDc0MTBjNGI3NWMxZjIyOTgxZTVkYjk4MzZhODg2M2MxMzFiNzFjZDUxZGQxYjYwYjhjNDVkYjM1ODA4ZmI3OSZYLUFtei1TaWduZWRIZWFkZXJzPWhvc3QmYWN0b3JfaWQ9MCZrZXlfaWQ9MCZyZXBvX2lkPTAifQ.iiRGr_yWJVVrft-ma2JMzDh22nRSBd9RunYwkhTPIY8)

You can also pull them out of local/remote IPSWs

```bash
❯ 
ipsw extract --fcs-key iPhone16,2_18.0_22A5307f_Restore.ipsw
   • Extracting AEA1 DMG fcs-keys
      • Created 22A5307f__iPhone16,2/090-29713-065.dmg.aea.pem
      • Created 22A5307f__iPhone16,2/090-27454-052.dmg.aea.pem
```

Now extract one of these pesky `.dmg.aea` files

```bash
❯ ipsw extract --dmg sys iPhone16,2_18.0_22A5307f_Restore.ipsw
   • Extracting DMG           
        1.50 GiB / 1.50 GiB [==========================================================| ✅  ] 1.50 GiB/s
        229.00 b / 229.00 b [==========================================================| ✅  ] 
        2.04 KiB / 2.04 KiB [==========================================================| ✅  ] 
      • Created 22A5307f__iPhone16,2/090-29713-065.dmg.aea
      • Created 22A5307f__iPhone16,2/Firmware/090-29713-065.dmg.aea.root_hash
      • Created 22A5307f__iPhone16,2/Firmware/090-29713-065.dmg.aea.trustcache
```

### Use an extracted PEM file to decrypt a `*.dmg.aea` file

```bash
❯ ipsw fw aea --pem '22A5307f__iPhone16,2/090-29713-065.dmg.aea.pem' 
                    '22A5307f__iPhone16,2/090-29713-065.dmg.aea' --output /tmp
   • Extracted AEA to /tmp/090-29713-065.dmg
```

### Dump all the AEA metadata from a local AEA file

This parses the AEA header and metadata and presents it for you in `--color`

![image](https://private-user-images.githubusercontent.com/6118188/338740737-920287ff-033a-4fdc-beee-63068b0b6a43.png?jwt=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJnaXRodWIuY29tIiwiYXVkIjoicmF3LmdpdGh1YnVzZXJjb250ZW50LmNvbSIsImtleSI6ImtleTUiLCJleHAiOjE3MjA0OTkzNzEsIm5iZiI6MTcyMDQ5OTA3MSwicGF0aCI6Ii82MTE4MTg4LzMzODc0MDczNy05MjAyODdmZi0wMzNhLTRmZGMtYmVlZS02MzA2OGIwYjZhNDMucG5nP1gtQW16LUFsZ29yaXRobT1BV1M0LUhNQUMtU0hBMjU2JlgtQW16LUNyZWRlbnRpYWw9QUtJQVZDT0RZTFNBNTNQUUs0WkElMkYyMDI0MDcwOSUyRnVzLWVhc3QtMSUyRnMzJTJGYXdzNF9yZXF1ZXN0JlgtQW16LURhdGU9MjAyNDA3MDlUMDQyNDMxWiZYLUFtei1FeHBpcmVzPTMwMCZYLUFtei1TaWduYXR1cmU9MTI0OGVhMGZlY2NjOWU1ZGNlNjkxMWQ2NzViOTViODFlZGRmOTA0ZDgyNTUyYTNiMTY1MTgyMjk1YzVhMjBlYiZYLUFtei1TaWduZWRIZWFkZXJzPWhvc3QmYWN0b3JfaWQ9MCZrZXlfaWQ9MCZyZXBvX2lkPTAifQ.WNRvohKxiEXP1fCxKeKR6ONzF3qjIXwePQzIZm8PIf0)


### Extract the AEA private key that you can use with the `aea` binary to decrypt the `*.dmg.aea`

```bash
❯ ipsw fw aea --key iPhone16,2_18.0_22A5282m_Restore/090-27454-036.dmg.aea

base64:S8f/KZsKuRXg/RnkMlG6SWiFtSPlmwz9YFdBnyPc1EQ=
```

```bash
❯ aea decrypt -i iPhone16,2_18.0_22A5282m_Restore/090-27454-036.dmg.aea -o TEST.dmg -key-value 'base64:S8f/KZsKuRXg/RnkMlG6SWiFtSPlmwz9YFdBnyPc1EQ='
```

You can also dump the key in the JSON database form

```bash
❯ ipsw fw aea --fcs-key iPhone16,2_18.0_22A5282m_Restore/090-27454-036.dmg.aea
   • Created fcs-keys.json    
```   
```json   
{
  "C76OEoiX5Lfc0nRQtn1cLkOEwDtC8HGIM_M_1rJgQ9g=": "LS0tLS1CRUdJTiBQUklWQVRFIEtFWS0tLS0tCk1JR0hBZ0VBTUJNR0J5cUdTTTQ5QWdFR0NDcUdTTTQ5QXdFSEJHMHdhd0lCQVFRZ21qWDBwYmU2WWErMDJUek4KY0laWHZ6L1VId1lMN1JwUVFka01QV1pmT2UraFJBTkNBQVRzeUsxZEJzUFJVZU15b2hWM2VJUG5JNGw2SzhjUApWeGZGRXBEd01DdXNlTUVrV0UzV0w5QXcvTTMyRk5Ta2lYZUNpQXoxMXBOdUJVWGVmTkFPSXlkSQotLS0tLUVORCBQUklWQVRFIEtFWS0tLS0tCg=="
}
```

### Download AEA PEMs as JSON form remote IPSWs *(using `ipsw`'s patent pending **partial-partialzip** ™️)* 

![image](https://private-user-images.githubusercontent.com/6118188/338740222-76981c6f-0881-4c8c-88e3-e2ff75cbfa9a.png?jwt=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJnaXRodWIuY29tIiwiYXVkIjoicmF3LmdpdGh1YnVzZXJjb250ZW50LmNvbSIsImtleSI6ImtleTUiLCJleHAiOjE3MjA0OTkzNzEsIm5iZiI6MTcyMDQ5OTA3MSwicGF0aCI6Ii82MTE4MTg4LzMzODc0MDIyMi03Njk4MWM2Zi0wODgxLTRjOGMtODhlMy1lMmZmNzVjYmZhOWEucG5nP1gtQW16LUFsZ29yaXRobT1BV1M0LUhNQUMtU0hBMjU2JlgtQW16LUNyZWRlbnRpYWw9QUtJQVZDT0RZTFNBNTNQUUs0WkElMkYyMDI0MDcwOSUyRnVzLWVhc3QtMSUyRnMzJTJGYXdzNF9yZXF1ZXN0JlgtQW16LURhdGU9MjAyNDA3MDlUMDQyNDMxWiZYLUFtei1FeHBpcmVzPTMwMCZYLUFtei1TaWduYXR1cmU9MDUxNGZjYzMxMDQxZTRkZThhNjU2MDZkNGM0MzcyYTE0NTY0NWI0NmZmZjljMGRjMmZmZDM3MmI1ZWUwZjY4ZSZYLUFtei1TaWduZWRIZWFkZXJzPWhvc3QmYWN0b3JfaWQ9MCZrZXlfaWQ9MCZyZXBvX2lkPTAifQ.z569RaLs_ubVyZ8p-A-WeAite0JpxgKbPxsbDalQDtU)

> [!NOTE]
> It appears AAPL is only using 1 private key per mobile per version? Thx AAPL ❤️  

### This `fcs-keys.json` is what I'm refering to as an *AEA PEM JSON Database* and it can be used offline via the `--pem-db` flag on several `ipsw` commands.

```bash
❯ ipsw mount fs --pem-db 'fcs-keys.json' iPhone16,2_18.0_22A5282m_Restore.ipsw
   • Mounted fs DMG 090-27454-036.dmg
      • Press Ctrl+C to unmount '/tmp/090-27454-036.dmg.mount' ...
```



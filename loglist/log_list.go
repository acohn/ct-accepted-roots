// Code generated by generate.go using go generate. DO NOT EDIT.
// Generated at
//  RFC1119
// using data from
// [https://www.gstatic.com/ct/log_list/all_logs_list.json https://ct.grahamedgecombe.com/logs.json]

package main

import "github.com/acohn/ct-accepted-roots/loglist/schema"

var Logs = []schema.Log{
	{Key: "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAETtK8v7MICve56qTHHDhhBOuV4IlUaESxZryCfk9QbG9co/CqPvTsgPDbCpp6oFtyAHwlDhnvr7JijXRD9Cb2FA==", Description: "Google Icarus", Url: "https://ct.googleapis.com/icarus", MaximumMergeDelay: 86400},
	{Key: "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEEmyGDvYXsRJsNyXSrYc9DjHsIa2xzb4UR7ZxVoV6mrc9iZB7xjI6+NrOiwH+P/xxkRmOFG6Jel20q37hTh58rA==", Description: "Google Skydiver", Url: "https://ct.googleapis.com/skydiver", MaximumMergeDelay: 86400},
	{Key: "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEbgwcuu4rakGFYB17fqsILPwMCqUIsz7VcCTRbR0ttrfzizbcI02VYxK75IaNzOnR7qFAot8LowYKMMqNrKQpVg==", Description: "Google Daedalus", Url: "https://ct.googleapis.com/daedalus", MaximumMergeDelay: 604800},
	{Key: "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEowJkhCK7JewN47zCyYl93UXQ7uYVhY/Z5xcbE4Dq7bKFN61qxdglnfr0tPNuFiglN+qjN2Syxwv9UeXBBfQOtQ==", Description: "Symantec Sirius", Url: "https://sirius.ws.symantec.com", MaximumMergeDelay: 86400},
	{Key: "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE0gBVBa3VR7QZu82V+ynXWD14JM3ORp37MtRxTmACJV5ZPtfUA7htQ2hofuigZQs+bnFZkje+qejxoyvk2Q1VaA==", Description: "Google Argon 2018", Url: "https://ct.googleapis.com/logs/argon2018", MaximumMergeDelay: 86400},
	{Key: "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE6pWeAv/u8TNtS4e8zf0ZF2L/lNPQWQc/Ai0ckP7IRzA78d0NuBEMXR2G3avTK0Zm+25ltzv9WWis36b4ztIYTQ==", Description: "Symantec Vega", Url: "https://vega.ws.symantec.com", MaximumMergeDelay: 86400},
	{Key: "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEluqsHEYMG1XcDfy1lCdGV0JwOmkY4r87xNuroPS2bMBTP01CEDPwWJePa75y9CrsHEKqAy8afig1dpkIPSEUhg==", Description: "Symantec", Url: "https://ct.ws.symantec.com", MaximumMergeDelay: 86400},
	{Key: "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEloIeo806gIQel7i3BxmudhoO+FV2nRIzTpGI5NBIUFzBn2py1gH1FNbQOG7hMrxnDTfouiIQ0XKGeSiW+RcemA==", Description: "Symantec Deneb", Url: "https://deneb.ws.symantec.com", MaximumMergeDelay: 86400},
	{Key: "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE6Tx2p1yKY4015NyIYvdrk36es0uAc1zA4PQ+TGRY+3ZjUTIYY9Wyu+3q/147JG4vNVKLtDWarZwVqGkg6lAYzA==", Description: "Google Argon 2020", Url: "https://ct.googleapis.com/logs/argon2020", MaximumMergeDelay: 86400},
	{Key: "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEe9de7LmmJcJERiLqoBniAD+XENbtmVNjeOhtaK/DF7s8jvp0why9powt4pKSkaZdWO/mjhGWIblq/k4D0gXoSg==", Description: "WoTrus", Url: "https://ctlog.wotrus.com", MaximumMergeDelay: 86400},
	{Key: "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEx6zC8wCbMs3fpQWnSCeo2RvG827AEssGkMa+5RVIpRF0SDO4hFsn2Ph1l8marSCuwVLhv0JIN3arSzbUieX6HA==", Description: "GDCA 2", Url: "https://log2.gdca.com.cn", MaximumMergeDelay: 86400},
	{Key: "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAolpIHxdSlTXLo1s6H1OCdpSj/4DyHDc8wLG9wVmLqy1lk9fz4ATVmm+/1iN2Nk8jmctUKK2MFUtlWXZBSpym97M7frGlSaQXUWyA3CqQUEuIJOmlEjKTBEiQAvpfDjCHjlV2Be4qTM6jamkJbiWtgnYPhJL6ONaGTiSPm7Byy57iaz/hbckldSOIoRhYBiMzeNoA0DiRZ9KmfSeXZ1rB8y8X5urSW+iBzf2SaOfzBvDpcoTuAaWx2DPazoOl28fP1hZ+kHUYvxbcMjttjauCFx+JII0dmuZNIwjfeG/GBb9frpSX219k1O4Wi6OEbHEr8at/XQ0y7gTikOxBn/s5wQIDAQAB", Description: "Venafi", Url: "https://ctlog.api.venafi.com", MaximumMergeDelay: 86400},
	{Key: "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAETeBmZOrzZKo4xYktx9gI2chEce3cw/tbr5xkoQlmhB18aKfsxD+MnILgGNl0FOm0eYGilFVi85wLRIOhK8lxKw==", Description: "Google Argon 2021", Url: "https://ct.googleapis.com/logs/argon2021", MaximumMergeDelay: 86400},
	{Key: "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAESPNZ8/YFGNPbsu1Gfs/IEbVXsajWTOaft0oaFIZDqUiwy1o/PErK38SCFFWa+PeOQFXc9NKv6nV0+05/YIYuUQ==", Description: "StartCom", Url: "https://ct.startssl.com", MaximumMergeDelay: 86400},
	{Key: "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEI3MQm+HzXvaYa2mVlhB4zknbtAT8cSxakmBoJcBKGqGwYS0bhxSpuvABM1kdBTDpQhXnVdcq+LSiukXJRpGHVg==", Description: "Google Argon 2019", Url: "https://ct.googleapis.com/logs/argon2019", MaximumMergeDelay: 86400},
	{Key: "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEfahLEimAoz2t01p3uMziiLOl/fHTDM0YDOhBRuiBARsV4UvxG2LdNgoIGLrtCzWE0J5APC2em4JlvR8EEEFMoA==", Description: "Google Pilot", Url: "https://ct.googleapis.com/pilot", MaximumMergeDelay: 86400},
	{Key: "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEzVH/qe+rgr/Mo+owQ00I6aegDSjHttgqQBmg+hBdTXXLgJT/+8LdSgjfY/8lOBtfivndJzQlTNQ9Le1cU6wXNQ==", Description: "GDCA 1", Url: "https://log.gdca.com.cn", MaximumMergeDelay: 86400},
	{Key: "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEjicnerZVCXTrbEuUhGW85BXx6lrYfA43zro/bAna5ymW00VQb94etBzSg4j/KS/Oqf/fNN51D8DMGA2ULvw3AQ==", Description: "Venafi Gen2", Url: "https://ctlog-gen2.api.venafi.com", MaximumMergeDelay: 86400},
	{Key: "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEVG18id3qnfC6X/RtYHo3TwIlvxz2b4WurxXfaW7t26maKZfymXYe5jNGHif0vnDdWde6z/7Qco6wVw+dN4liow==", Description: "Google Argon 2017", Url: "https://ct.googleapis.com/logs/argon2017", MaximumMergeDelay: 86400},
	{Key: "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE8m/SiQ8/xfiHHqtls9m7FyOMBg4JVZY9CgiixXGz0akvKD6DEL8S0ERmFe9U4ZiA0M4kbT5nmuk3I85Sk4bagA==", Description: "Comodo Sabre", Url: "https://sabre.ct.comodo.com", MaximumMergeDelay: 86400},
	{Key: "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEIFsYyDzBi7MxCAC/oJBXK7dHjG+1aLCOkHjpoHPqTyghLpzA9BYbqvnV16mAw04vUjyYASVGJCUoI3ctBcJAeg==", Description: "Google Rocketeer", Url: "https://ct.googleapis.com/rocketeer", MaximumMergeDelay: 86400},
	{Key: "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEzF05L2a4TH/BLgOhNKPoioYCrkoRxvcmajeb8Dj4XQmNY+gxa4Zmz3mzJTwe33i0qMVp+rfwgnliQ/bM/oFmhA==", Description: "DigiCert 2", Url: "https://ct2.digicert-ct.com/log", MaximumMergeDelay: 86400},
	{Key: "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEAkbFvhu7gkAW6MHSrBlpE1n4+HCFRkC5OLAjgqhkTH+/uzSfSl8ois8ZxAD2NgaTZe1M9akhYlrYkes4JECs6A==", Description: "DigiCert 1", Url: "https://ct1.digicert-ct.com/log", MaximumMergeDelay: 86400},
	{Key: "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAv7UIYZopMgTTJWPp2IXhhuAf1l6a9zM7gBvntj5fLaFm9pVKhKYhVnno94XuXeN8EsDgiSIJIj66FpUGvai5samyetZhLocRuXhAiXXbDNyQ4KR51tVebtEq2zT0mT9liTtGwiksFQccyUsaVPhsHq9gJ2IKZdWauVA2Fm5x9h8B9xKn/L/2IaMpkIYtd967TNTP/dLPgixN1PLCLaypvurDGSVDsuWabA3FHKWL9z8wr7kBkbdpEhLlg2H+NAC+9nGKx+tQkuhZ/hWR65aX+CNUPy2OB9/u2rNPyDydb988LENXoUcMkQT0dU3aiYGkFAY0uZjD2vH97TM20xYtNQIDAQAB", Description: "CNNIC", Url: "https://ctserver.cnnic.cn", MaximumMergeDelay: 86400},
	{Key: "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAELPXCMfVjQ2oWSgrewu4fIW4Sfh3lco90CwKZ061pvAI1eflh6c8ACE90pKM0muBDHCN+j0HV7scco4KKQPqq4A==", Description: "Comodo Dodo", Url: "https://dodo.ct.comodo.com", MaximumMergeDelay: 86400},
	{Key: "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE7+R9dC4VFbbpuyOL+yy14ceAmEf7QGlo/EmtYU6DRzwat43f/3swtLr/L8ugFOOt1YU/RFmMjGCL17ixv66MZw==", Description: "Comodo Mammoth", Url: "https://mammoth.ct.comodo.com", MaximumMergeDelay: 86400},
	{Key: "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEWTmyppTGMrn+Y2keMDujW9WwQ8lQHpWlLadMSkmOi4+3+MziW5dy1eo/sSFI6ERrf+rvIv/f9F87bXcEsa+Qjw==", Description: "Behind The Sofa", Url: "https://ct.filippo.io/behindthesofa", MaximumMergeDelay: 86400},
	{Key: "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAErQ8wrZ55pDiJJlSGq0FykG/7yhemrO7Gn30CBexBqMdBnTJJrbA5vTqHPnzuaGxg0Ucqk67hQPQLyDU8HQ9l0w==", Description: "GDCA (Old 1)", Url: "https://ct.gdca.com.cn", MaximumMergeDelay: 86400},
	{Key: "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEW0rHAbd0VLpAnEN1lD+s77NxVrjT4nuuobE+U6qXM6GCu19dHAv6hQ289+Wg4CLwoInZCn9fJpTTJOOZLuQVjQ==", Description: "GDCA (Old 2)", Url: "https://ctlog.gdca.com.cn", MaximumMergeDelay: 86400},
	{Key: "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEOfifIGLUV1Voou9JLfA5LZreRLSUMOCeeic8q3Dw0fpRkGMWV0Gtq20fgHQweQJeLVmEByQj9p81uIW4QkWkTw==", Description: "Google Submariner", Url: "https://ct.googleapis.com/submariner", MaximumMergeDelay: 86400},
	{Key: "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEw8i8S7qiGEs9NXv0ZJFh6uuOmR2Q7dPprzk9XNNGkUXjzqx2SDvRfiwKYwBljfWujozHESVPQyydGaHhkaSz/g==", Description: "Google Test Tube", Url: "https://ct.googleapis.com/testtube", MaximumMergeDelay: 86400},
	{Key: "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEeZDnIspLwTkFAVMsbCuu2GExJLQsj17+IyI6Gcc2u1kCMBbl6NSi3bAPSmkRVCnIvpkFy70Lk3fVdNEhvCXOoQ==", Description: "WoTrus 3", Url: "https://ctlog3.wotrus.com", MaximumMergeDelay: 86400},
	{Key: "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE9UV9+jO2MCTzkabodO2F7LM03MUBc8MrdAtkcW6v6GA9taTTw9QJqofm0BbdAsbtJL/unyEf0zIkRgXjjzaYqQ==", Description: "NORDUnet Plausible", Url: "https://plausible.ct.nordu.net", MaximumMergeDelay: 86400},
	{Key: "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEzBGIey1my66PTTBmJxklIpMhRrQvAdPG+SvVyLpzmwai8IoCnNBrRhgwhbrpJIsO0VtwKAx+8TpFf1rzgkJgMQ==", Description: "WoSign", Url: "https://ctlog.wosign.com", MaximumMergeDelay: 86400},
}

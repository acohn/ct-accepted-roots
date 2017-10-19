// Code generated by generate.go using go generate. DO NOT EDIT.
// Generated at
//  Thu, 19 Oct 2017 16:27:05 UTC
// using data from
//  https://ct.grahamedgecombe.com/logs.json
//  https://www.gstatic.com/ct/log_list/all_logs_list.json

package main

import "github.com/acohn/ct-accepted-roots/loglist/schema"

var Logs = schema.LogList{Logs: []schema.Log{
	{
		Key:               "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEVG18id3qnfC6X/RtYHo3TwIlvxz2b4WurxXfaW7t26maKZfymXYe5jNGHif0vnDdWde6z/7Qco6wVw+dN4liow==",
		Description:       "Google 'Argon2017' log", // +tTJfMSe4vishcXqXOoJ0CINu/TknGtQZi/4aPhrjCg=
		Url:               "https://ct.googleapis.com/logs/argon2017/",
		MaximumMergeDelay: 86400,
	},
	{
		Key:               "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAELPXCMfVjQ2oWSgrewu4fIW4Sfh3lco90CwKZ061pvAI1eflh6c8ACE90pKM0muBDHCN+j0HV7scco4KKQPqq4A==",
		Description:       "Comodo 'Dodo' CT log", // 23b9raxl59CVCIhuIVm9i5A1L1/q0+PcXiLrNQrMe5g=
		Url:               "https://dodo.ct.comodo.com/",
		MaximumMergeDelay: 86400,
	},
	{
		Key:               "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEluqsHEYMG1XcDfy1lCdGV0JwOmkY4r87xNuroPS2bMBTP01CEDPwWJePa75y9CrsHEKqAy8afig1dpkIPSEUhg==",
		Description:       "Symantec log", // 3esdK3oNT6Ygi4GtgWhwfi6OnQHVXIiNPRHEzbbsvsw=
		Url:               "https://ct.ws.symantec.com/",
		MaximumMergeDelay: 86400,
	},
	{
		Key:               "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEIFsYyDzBi7MxCAC/oJBXK7dHjG+1aLCOkHjpoHPqTyghLpzA9BYbqvnV16mAw04vUjyYASVGJCUoI3ctBcJAeg==",
		Description:       "Google 'Rocketeer' log", // 7ku9t3XOYLrhQmkfq+GeZqMPfl+wctiDAMR7iXqo/cs=
		Url:               "https://ct.googleapis.com/rocketeer/",
		MaximumMergeDelay: 86400,
	},
	{
		Key:               "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAETeBmZOrzZKo4xYktx9gI2chEce3cw/tbr5xkoQlmhB18aKfsxD+MnILgGNl0FOm0eYGilFVi85wLRIOhK8lxKw==",
		Description:       "Google 'Argon2021' log", // 9lyUL9F3MCIUVBgIMJRWjuNNExkzv98MLyALzE7xZOM=
		Url:               "https://ct.googleapis.com/logs/argon2021/",
		MaximumMergeDelay: 86400,
	},
	{
		Key:               "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEjicnerZVCXTrbEuUhGW85BXx6lrYfA43zro/bAna5ymW00VQb94etBzSg4j/KS/Oqf/fNN51D8DMGA2ULvw3AQ==",
		Description:       "Venafi Gen2 CT log", // AwGd8/2FppqOvR+sxtqbpz5Gl3T+d/V5/FoIuDKMHWs=
		Url:               "https://ctlog-gen2.api.venafi.com/",
		MaximumMergeDelay: 86400,
	},
	{
		Key:               "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEx6zC8wCbMs3fpQWnSCeo2RvG827AEssGkMa+5RVIpRF0SDO4hFsn2Ph1l8marSCuwVLhv0JIN3arSzbUieX6HA==",
		Description:       "GDCA 2", // FDCNkMzQMBNQBcAcpSbYHoTodiTjm2JI4I9ySuo7tCo=
		Url:               "https://log2.gdca.com.cn",
		MaximumMergeDelay: 86400,
	},
	{
		Key:               "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEowJkhCK7JewN47zCyYl93UXQ7uYVhY/Z5xcbE4Dq7bKFN61qxdglnfr0tPNuFiglN+qjN2Syxwv9UeXBBfQOtQ==",
		Description:       "Symantec 'Sirius' log", // FZcEiNe5l6Bb61JRKt7o0ui0oxZSZBIan6v71fha2T8=
		Url:               "https://sirius.ws.symantec.com/",
		MaximumMergeDelay: 86400,
	},
	{
		Key:               "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEbgwcuu4rakGFYB17fqsILPwMCqUIsz7VcCTRbR0ttrfzizbcI02VYxK75IaNzOnR7qFAot8LowYKMMqNrKQpVg==",
		Description:       "Google 'Daedalus' log", // HQJLjrFJizRN/YfqPvwJlvdQbyNdHUlwYaR3PEOcJfs=
		Url:               "https://ct.googleapis.com/daedalus/",
		MaximumMergeDelay: 604800,
	},
	{
		Key:               "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAETtK8v7MICve56qTHHDhhBOuV4IlUaESxZryCfk9QbG9co/CqPvTsgPDbCpp6oFtyAHwlDhnvr7JijXRD9Cb2FA==",
		Description:       "Google 'Icarus' log", // KTxRllTIOWW6qlD8WAfUt2+/WHopctykwwz05UVH9Hg=
		Url:               "https://ct.googleapis.com/icarus/",
		MaximumMergeDelay: 86400,
	},
	{
		Key:               "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAESPNZ8/YFGNPbsu1Gfs/IEbVXsajWTOaft0oaFIZDqUiwy1o/PErK38SCFFWa+PeOQFXc9NKv6nV0+05/YIYuUQ==",
		Description:       "StartCom log", // NLtq1sPfnAPuqKSZ/3iRSGydXlysktAfe/0bzhnbSO8=
		Url:               "https://ct.startssl.com/",
		MaximumMergeDelay: 86400,
	},
	{
		Key:               "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEzBGIey1my66PTTBmJxklIpMhRrQvAdPG+SvVyLpzmwai8IoCnNBrRhgwhbrpJIsO0VtwKAx+8TpFf1rzgkJgMQ==",
		Description:       "WoSign log", // QbLcLonmPOSvG6e7Kb9oxt7m+fHMBH4w3/rjs7olkmM=
		Url:               "https://ctlog.wosign.com/",
		MaximumMergeDelay: 86400,
	},
	{
		Key:               "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE8m/SiQ8/xfiHHqtls9m7FyOMBg4JVZY9CgiixXGz0akvKD6DEL8S0ERmFe9U4ZiA0M4kbT5nmuk3I85Sk4bagA==",
		Description:       "Comodo 'Sabre' CT log", // VYHUwhaQNgFK6gubVzxT8MDkOHhwJQgXL6OqHQcT0ww=
		Url:               "https://sabre.ct.comodo.com/",
		MaximumMergeDelay: 86400,
	},
	{
		Key:               "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEAkbFvhu7gkAW6MHSrBlpE1n4+HCFRkC5OLAjgqhkTH+/uzSfSl8ois8ZxAD2NgaTZe1M9akhYlrYkes4JECs6A==",
		Description:       "DigiCert Log Server", // VhQGmi/XwuzT9eG9RLI+x0Z2ubyZEVzA75SYVdaJ0N0=
		Url:               "https://ct1.digicert-ct.com/log/",
		MaximumMergeDelay: 86400,
	},
	{
		Key:               "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEI3MQm+HzXvaYa2mVlhB4zknbtAT8cSxakmBoJcBKGqGwYS0bhxSpuvABM1kdBTDpQhXnVdcq+LSiukXJRpGHVg==",
		Description:       "Google 'Argon2019' log", // Y/Lbzeg7zCzPC3KEJ1drM6SNYXePvXWmOLHHaFRL2I0=
		Url:               "https://ct.googleapis.com/logs/argon2019/",
		MaximumMergeDelay: 86400,
	},
	{
		Key:               "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE7+R9dC4VFbbpuyOL+yy14ceAmEf7QGlo/EmtYU6DRzwat43f/3swtLr/L8ugFOOt1YU/RFmMjGCL17ixv66MZw==",
		Description:       "Comodo 'Mammoth' CT log", // b1N2rDHwMRnYmQCkURX/dxUcEdkCwQApBo2yCJo32RM=
		Url:               "https://mammoth.ct.comodo.com/",
		MaximumMergeDelay: 86400,
	},
	{
		Key:               "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEzVH/qe+rgr/Mo+owQ00I6aegDSjHttgqQBmg+hBdTXXLgJT/+8LdSgjfY/8lOBtfivndJzQlTNQ9Le1cU6wXNQ==",
		Description:       "GDCA 1", // cX6nQgl1voSicjVT8Xd8Jt1Rr04QIUQJTZAZtGL7Zmg=
		Url:               "https://log.gdca.com.cn",
		MaximumMergeDelay: 86400,
	},
	{
		Key:               "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEzF05L2a4TH/BLgOhNKPoioYCrkoRxvcmajeb8Dj4XQmNY+gxa4Zmz3mzJTwe33i0qMVp+rfwgnliQ/bM/oFmhA==",
		Description:       "DigiCert Log Server 2", // h3W/51l8+IxDmV+9827/Vo1HVjb/SrVgwbTq/16ggw8=
		Url:               "https://ct2.digicert-ct.com/log/",
		MaximumMergeDelay: 86400,
	},
	{
		Key:               "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEW0rHAbd0VLpAnEN1lD+s77NxVrjT4nuuobE+U6qXM6GCu19dHAv6hQ289+Wg4CLwoInZCn9fJpTTJOOZLuQVjQ==",
		Description:       "GDCA CT log #2", // kkow+Qkzb/Q11pk6EKx1osZBco5/wtZZrmGI/61AzgE=
		Url:               "https://ctlog.gdca.com.cn/",
		MaximumMergeDelay: 86400,
	},
	{
		Key:               "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEeZDnIspLwTkFAVMsbCuu2GExJLQsj17+IyI6Gcc2u1kCMBbl6NSi3bAPSmkRVCnIvpkFy70Lk3fVdNEhvCXOoQ==",
		Description:       "WoTrus 3", // mueOgrUnqTLVe4NZadQv4/Ah4TKZis8cN3oV+x5FLFo=
		Url:               "https://ctlog3.wotrus.com",
		MaximumMergeDelay: 86400,
	},
	{
		Key:               "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEe9de7LmmJcJERiLqoBniAD+XENbtmVNjeOhtaK/DF7s8jvp0why9powt4pKSkaZdWO/mjhGWIblq/k4D0gXoSg==",
		Description:       "WoTrus", // oXEni6iuir1G4jqDj74jdM4lWBrNpUBslrhxAEfpvsI=
		Url:               "https://ctlog.wotrus.com",
		MaximumMergeDelay: 86400,
	},
	{
		Key:               "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEloIeo806gIQel7i3BxmudhoO+FV2nRIzTpGI5NBIUFzBn2py1gH1FNbQOG7hMrxnDTfouiIQ0XKGeSiW+RcemA==",
		Description:       "Symantec Deneb", // p85KTmIH4K3e5f2qSx+GdodntdACpV1HMQ5+ZwqV6rI=
		Url:               "https://deneb.ws.symantec.com/",
		MaximumMergeDelay: 86400,
	},
	{
		Key:               "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE0gBVBa3VR7QZu82V+ynXWD14JM3ORp37MtRxTmACJV5ZPtfUA7htQ2hofuigZQs+bnFZkje+qejxoyvk2Q1VaA==",
		Description:       "Google 'Argon2018' log", // pFASaQVaFVReYhGrN7wQP2KuVXakXksXFEU+GyIQaiU=
		Url:               "https://ct.googleapis.com/logs/argon2018/",
		MaximumMergeDelay: 86400,
	},
	{
		Key:               "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEfahLEimAoz2t01p3uMziiLOl/fHTDM0YDOhBRuiBARsV4UvxG2LdNgoIGLrtCzWE0J5APC2em4JlvR8EEEFMoA==",
		Description:       "Google 'Pilot' log", // pLkJkLQYWBSHuxOizGdwCjw1mAT5G9+443fNDsgN3BA=
		Url:               "https://ct.googleapis.com/pilot/",
		MaximumMergeDelay: 86400,
	},
	{
		Key:               "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAv7UIYZopMgTTJWPp2IXhhuAf1l6a9zM7gBvntj5fLaFm9pVKhKYhVnno94XuXeN8EsDgiSIJIj66FpUGvai5samyetZhLocRuXhAiXXbDNyQ4KR51tVebtEq2zT0mT9liTtGwiksFQccyUsaVPhsHq9gJ2IKZdWauVA2Fm5x9h8B9xKn/L/2IaMpkIYtd967TNTP/dLPgixN1PLCLaypvurDGSVDsuWabA3FHKWL9z8wr7kBkbdpEhLlg2H+NAC+9nGKx+tQkuhZ/hWR65aX+CNUPy2OB9/u2rNPyDydb988LENXoUcMkQT0dU3aiYGkFAY0uZjD2vH97TM20xYtNQIDAQAB",
		Description:       "CNNIC CT log", // pXesnO11SN2PAltnokEInfhuD0duwgPC7L7bGF8oJjg=
		Url:               "https://ctserver.cnnic.cn/",
		MaximumMergeDelay: 86400,
	},
	{
		Key:               "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEOfifIGLUV1Voou9JLfA5LZreRLSUMOCeeic8q3Dw0fpRkGMWV0Gtq20fgHQweQJeLVmEByQj9p81uIW4QkWkTw==",
		Description:       "Google 'Submariner' log", // qJnYeAySkKr0YvMYgMz71SRR6XDQ+/WR73Ww2ZtkVoE=
		Url:               "https://ct.googleapis.com/submariner/",
		MaximumMergeDelay: 86400,
	},
	{
		Key:               "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE9UV9+jO2MCTzkabodO2F7LM03MUBc8MrdAtkcW6v6GA9taTTw9QJqofm0BbdAsbtJL/unyEf0zIkRgXjjzaYqQ==",
		Description:       "Nordu 'plausible' log", // qucLfzy41WbIbC8Wl5yfRF9pqw60U1WJsvd6AwEE880=
		Url:               "https://plausible.ct.nordu.net/",
		MaximumMergeDelay: 86400,
	},
	{
		Key:               "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAolpIHxdSlTXLo1s6H1OCdpSj/4DyHDc8wLG9wVmLqy1lk9fz4ATVmm+/1iN2Nk8jmctUKK2MFUtlWXZBSpym97M7frGlSaQXUWyA3CqQUEuIJOmlEjKTBEiQAvpfDjCHjlV2Be4qTM6jamkJbiWtgnYPhJL6ONaGTiSPm7Byy57iaz/hbckldSOIoRhYBiMzeNoA0DiRZ9KmfSeXZ1rB8y8X5urSW+iBzf2SaOfzBvDpcoTuAaWx2DPazoOl28fP1hZ+kHUYvxbcMjttjauCFx+JII0dmuZNIwjfeG/GBb9frpSX219k1O4Wi6OEbHEr8at/XQ0y7gTikOxBn/s5wQIDAQAB",
		Description:       "Venafi log", // rDua7X+pZ0dXFZ5tfVdWcvnZgQCUHpve/+yhMTt1eC0=
		Url:               "https://ctlog.api.venafi.com/",
		MaximumMergeDelay: 86400,
	},
	{
		Key:               "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEWTmyppTGMrn+Y2keMDujW9WwQ8lQHpWlLadMSkmOi4+3+MziW5dy1eo/sSFI6ERrf+rvIv/f9F87bXcEsa+Qjw==",
		Description:       "Up In The Air 'Behind the Sofa' log", // sLeEvIHA3cR1ROiD8FmFu5B30TTYq4iysuUzmAuOUIs=
		Url:               "https://ct.filippo.io/behindthesofa/",
		MaximumMergeDelay: 86400,
	},
	{
		Key:               "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEw8i8S7qiGEs9NXv0ZJFh6uuOmR2Q7dPprzk9XNNGkUXjzqx2SDvRfiwKYwBljfWujozHESVPQyydGaHhkaSz/g==",
		Description:       "Google 'Testtube' log", // sMyD5aX5fWuvfAnMKEkEhyrH6IsTLGNQt8b9JuFsbHc=
		Url:               "https://ct.googleapis.com/testtube/",
		MaximumMergeDelay: 86400,
	},
	{
		Key:               "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE6Tx2p1yKY4015NyIYvdrk36es0uAc1zA4PQ+TGRY+3ZjUTIYY9Wyu+3q/147JG4vNVKLtDWarZwVqGkg6lAYzA==",
		Description:       "Google 'Argon2020' log", // sh4FzIuizYogTodm+Su5iiUgZ2va+nDnsklTLe+LkF4=
		Url:               "https://ct.googleapis.com/logs/argon2020/",
		MaximumMergeDelay: 86400,
	},
	{
		Key:               "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEEmyGDvYXsRJsNyXSrYc9DjHsIa2xzb4UR7ZxVoV6mrc9iZB7xjI6+NrOiwH+P/xxkRmOFG6Jel20q37hTh58rA==",
		Description:       "Google 'Skydiver' log", // u9nfvB+KcbWTlCOXqpJ7RzhXlQqrUugakJZkNo4e0YU=
		Url:               "https://ct.googleapis.com/skydiver/",
		MaximumMergeDelay: 86400,
	},
	{
		Key:               "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE6pWeAv/u8TNtS4e8zf0ZF2L/lNPQWQc/Ai0ckP7IRzA78d0NuBEMXR2G3avTK0Zm+25ltzv9WWis36b4ztIYTQ==",
		Description:       "Symantec 'Vega' log", // vHjh38X2PGhGSTNNoQ+hXwl5aSAJwIG08/aRfz7ZuKU=
		Url:               "https://vega.ws.symantec.com/",
		MaximumMergeDelay: 86400,
	},
	{
		Key:               "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAErQ8wrZ55pDiJJlSGq0FykG/7yhemrO7Gn30CBexBqMdBnTJJrbA5vTqHPnzuaGxg0Ucqk67hQPQLyDU8HQ9l0w==",
		Description:       "GDCA CT log #1", // yc+JCiEQnGZswXo+0GXJMNDgE1qf66ha8UIQuAckIao=
		Url:               "https://ct.gdca.com.cn/",
		MaximumMergeDelay: 86400,
	},
}}

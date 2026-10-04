# Run these targets inside the Dev Container (Go 1.26), not on the host.

.PHONY: dev agent migrate artisan test tidy check

# Тег сборки dev — единственный признак среды разработки (панель слушает все
# адреса контейнера). Сборка пакета его не знает: в клиентском бинарнике
# этой ветки нет.
dev:
	go run -tags dev .

# DEV-заглушка root-агента (обычный пользователь, сокет из .env AGENT_SOCKET).
agent:
	go run -tags dev ./cmd/vpn-agent

# Миграции БД (запустить один раз перед первым make dev и после обновления кода).
migrate:
	go run . artisan migrate

artisan:
	go run . artisan $(ARGS)

test:
	go test ./...

# Обе сборки (клиентская и с тегом dev) обязаны собираться и проходить vet.
check:
	go build ./... && go build -tags dev ./... && go vet ./... && go vet -tags dev ./...

tidy:
	go mod tidy

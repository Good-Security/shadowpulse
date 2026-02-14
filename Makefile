.PHONY: install dev dev-backend dev-frontend docker-up docker-down docker-logs tools-build db-up db-down db-psql db-reset

# Local development
install:
	cd backend && python3 -m venv .venv && . .venv/bin/activate && pip install -r requirements.txt
	cd frontend && npm install

dev:
	make dev-backend & make dev-frontend & wait

dev-backend:
	cd backend && . .venv/bin/activate && alembic upgrade head && uvicorn main:app --reload --port 8000

dev-frontend:
	cd frontend && npm run dev

# Docker
docker-up:
	docker compose up --build -d
	@echo ""
	@echo "SHADOWPULSE is running:"
	@echo "  Frontend: http://localhost:3000"
	@echo "  Backend:  http://localhost:8000"
	@echo "  Logs:     make docker-logs"
	@echo "  Stop:     make docker-down"

docker-down:
	docker compose down

docker-logs:
	docker compose logs -f

docker-logs-backend:
	docker compose logs -f backend

tools-build:
	docker compose build tools

tools-shell:
	docker exec -it shadowpulse-tools sh

# Database
db-up:
	docker compose up -d postgres

db-down:
	docker compose stop postgres

db-psql:
	docker compose exec postgres psql -U shadowpulse -d shadowpulse

db-reset:
	docker compose down -v

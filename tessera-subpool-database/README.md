Start database with:
```
sudo docker run -d --name tessera-pg \
  -e POSTGRES_USER=tessera \
  -e POSTGRES_PASSWORD=tessera \
  -e POSTGRES_DB=tessera_subpool \
  -p 5432:5432 \
  postgres:16
```

Create .env file with necessary variables. Then start the server with:
```
cargo run --release
```

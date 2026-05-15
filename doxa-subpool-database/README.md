Start database with:
```
docker run -d --name doxa-pg \
  -e POSTGRES_USER=doxa \
  -e POSTGRES_PASSWORD=doxa \
  -e POSTGRES_DB=doxa_subpool \
  -p 5432:5432 \
  postgres:16
```

Create .env file with necessary variables. Then start the server with:
```
cargo run --release
```

reset db:

```
sudo docker exec -i doxa-pg psql -U doxa -d postgres -c "DROP DATABASE doxa_subpool;" && \
sudo docker exec -i doxa-pg psql -U doxa -d postgres -c "CREATE DATABASE doxa_subpool;"
```

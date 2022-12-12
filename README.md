# VRLog: Voter Registration Transparency

VRLog provides a transparent record of voter registration data using transparency logs.

## Setup

1. Download trillian version 1.3.12: `git clone https://github.com/google/trillian && git checkout 4e6e1221e01dd615e0286a5eeeaf6f974e354f6e`
2. In the trillian folder, run `docker-compose -f examples/deployment/docker-compose.yml up`.
3. Run `make createmap` to generate the map.

## Running

1. Run `make mapper` to start the server.
2. Navigate to `http://localhost:8084`

## API

VRLog supports the following API endpoints:

- `POST /voter`

Creates or updates a voter. `id` is required.

Example body:

`{"firstName": "Test", "lastName": "Voter", "id": "1234"}`

- `GET /voter?id=id`

Fetches the stored entry given the public id.

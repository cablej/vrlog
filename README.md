# VRLog: Voter Registration Transparency

VRLog provides a transparent record of voter registration data using transparency logs.

Note that election officials are expected to authenticate voters separately before modifying their record.

## Setup

1. Download trillian version 1.3.12: `git clone https://github.com/google/trillian && git checkout 4e6e1221e01dd615e0286a5eeeaf6f974e354f6e`
2. Create the volume: `docker volume create --name=trillian-data`
3. In the trillian folder, run `docker-compose -f examples/deployment/docker-compose.yml up`.
4. Run `make createmap && make createlog && make createmaplog` to generate the map.

## Running

1. Run `go get github.com/google/trillian@4e6e1221e01dd615e0286a5eeeaf6f974e354f6e`
2. Run `make mapper` to start the server.
3. Navigate to `http://localhost:8084`

## API

VRLog supports the following API endpoints:

#### `POST /voter`

Creates or updates a voter. `id` is required.

Example body:

`{"firstName": "Test", "lastName": "Voter", "id": "1234"}`

#### `GET /voter?id=id`

Fetches the stored entry given the public id.

#### `DELETE /voter?id=id`

Marks the voter registration as inactive given the public id.

#### `GET /voter/prove?id=id`

Returns the membership proof for the given public id.

#### `POST /voter/verify`

Verifies the supplied membership proof.

#### `GET /voter/proveAppendOnly?first_tree_size=size`

Proves that the log is append only up to the specified first size.

#### `POST /voter/verifyAppendOnly`

Verifies that the log is append only up to the specified first size.

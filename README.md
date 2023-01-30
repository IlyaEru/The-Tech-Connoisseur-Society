# The Tech Connoisseur Society

## [Live Preview]()

## Description

This is a The Tech Connoisseur Society Clubhouse. It is a place where you can share your thoughts and opinions about the latest tech news. You can also see what other members are thinking about the latest tech news. You can only see the author of a post and the post Date only if you are a member of the society.

## Features

- Secure sign-up and login using passport.js
- Members can write anonymous posts with title and content
- Only members can see the author and date of each message
- Option for users to become members by entering a secret passcode
- Option for users to become admin and delete messages
- Display all member messages on the home page

## Getting Started

These instructions will get you a copy of the project up and running on your local machine for development and testing purposes.

### Prerequisites

You will need to have Node.js and npm (Node Package Manager) installed on your machine. You can download and install them from the official website (https://nodejs.org/en/).

### Installing

1. Clone the repository to your local machine

```sh
git clone https://github.com/IlyaEru/The-Tech-Connoisseur-Society.git
```

2. Install NPM packages

```sh
npm install
```

or

```sh
yarn install
```

or (my favorite)

```sh
pnpm install
```

3. Create a .env file in the root directory of the project with the environment variables, like the .env.example file

4. Populate the database with some data

```sh
npm run populate
```

5. Run the app

```sh
npm start
```

or for development

```sh
npm run devstart

```

The application will now be running on http://localhost:3000.

## Built With

- TypeScript - Typed superset of JavaScript
- Express - Web framework for Node.js
- EJS - Embedded JavaScript templating
- MongoDB - NoSQL database
- Mongoose - MongoDB object modeling tool
- Sass - CSS preprocessor
- Jest - JavaScript testing framework
- Mongodb-memory-server - MongoDB in-memory server for testing

## Testing

To run the tests, run the following command

```sh
npm test
```

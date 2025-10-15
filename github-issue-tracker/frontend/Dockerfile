# Use Node.js official image as base
FROM node:16

# Set working directory
WORKDIR /app

# Copy package.json and install dependencies
COPY package.json ./
RUN npm install

# Copy the rest of the application
COPY . /app

# Build the React app
RUN npm run build

# Serve the app using serve (you can use any static file server)
RUN npm install -g serve
CMD ["serve", "-s", "build", "-l", "80"]

# Expose port 80 for frontend
EXPOSE 80

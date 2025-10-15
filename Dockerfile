# Use Node.js 18 LTS
FROM node:18

# Set working directory
WORKDIR /app

# Copy only package files first for efficient caching
COPY ./package*.json ./

# Install dependencies
RUN npm install

# Copy the rest of your application code
COPY . .

# Expose backend port
EXPOSE 4000

# Start the server
CMD ["node", "src/server.js"]

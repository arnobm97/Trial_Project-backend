// server.js
require('dotenv').config();
const express = require('express');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const { MongoClient, ServerApiVersion, ObjectId } = require('mongodb');

const app = express();
const port = process.env.PORT || 5000;

app.use(cors());
app.use(express.json());

// MongoDB connection using your credentials
const uri = `mongodb+srv://${process.env.DB_USER}:${process.env.DB_PASS}@cluster0.drnmuvg.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0`;

// Create MongoClient
const client = new MongoClient(uri, {
  serverApi: {
    version: ServerApiVersion.v1,
    strict: true,
    deprecationErrors: true,
  }
});

async function run() {
  try {
    await client.connect();
    console.log("Connected to MongoDB successfully!");

    const db = client.db("rentalDb");
    const userCollection = db.collection("users");
    const menuCollection = db.collection("menu");
    const reviewsCollection = db.collection("reviews");
    const cartCollection = db.collection("carts");

    /********** JWT Secret from your environment **********/
    const JWT_SECRET = process.env.ACCESS_TOKEN_SECRET;

    /********** Helper: verify JWT token **********/
    const verifyToken = (req, res, next) => {
      const authHeader = req.headers.authorization;

      if (!authHeader || !authHeader.startsWith("Bearer ")) {
        return res.status(401).send({ message: "No token provided" });
      }

      const token = authHeader.split(" ")[1];

      try {
        const decoded = jwt.verify(token, JWT_SECRET);
        req.decoded = decoded;
        next();
      } catch (error) {
        console.error("JWT verification error:", error);
        return res.status(401).send({ message: "Unauthorized access" });
      }
    };

    // Helper to check if requester is admin
    const checkIfRequesterIsAdmin = async (req) => {
      try {
        const email = req.decoded?.email;
        if (!email) return false;
        const requester = await userCollection.findOne({ email });
        return requester?.role === 'admin';
      } catch (err) {
        console.error("checkIfRequesterIsAdmin error:", err);
        return false;
      }
    };

    /********** Routes **********/

    // Health check
    app.get('/', (req, res) => {
      res.send('Rental Server is Running!');
    });

    // Issue a backend JWT
    app.post('/jwt', async (req, res) => {
      const user = req.body;
      if (!user?.email) {
        return res.status(400).send({ message: 'email required' });
      }
      
      const token = jwt.sign({ email: user.email }, JWT_SECRET, { expiresIn: '1h' });
      res.send({ token });
    });

    // Get all users (admin only)
    app.get('/users', verifyToken, async (req, res) => {
      const isAdmin = await checkIfRequesterIsAdmin(req);
      if (!isAdmin) return res.status(403).send({ message: 'forbidden access' });
      
      try {
        const result = await userCollection.find().toArray();
        res.send(result);
      } catch (error) {
        res.status(500).send({ message: "Error fetching users" });
      }
    });

    // Check admin by email
    app.get('/users/admin/:email', verifyToken, async (req, res) => {
      const email = req.params.email;

      // Allow requester to check own email OR allow admins to check others
      if (req.decoded.email !== email) {
        const reqIsAdmin = await checkIfRequesterIsAdmin(req);
        if (!reqIsAdmin) return res.status(403).send({ message: 'forbidden access' });
      }

      try {
        const user = await userCollection.findOne({ email });
        const isAdmin = user?.role === 'admin';
        res.send({ admin: !!isAdmin });
      } catch (error) {
        res.status(500).send({ message: "Error checking admin status" });
      }
    });

    // Create regular user (public - no auth required)
    app.post('/users', async (req, res) => {
      try {
        const user = req.body;
        if (!user?.email) return res.status(400).send({ message: 'email required' });

        const query = { email: user.email };
        const existingUser = await userCollection.findOne(query);
        if (existingUser) {
          return res.send({ message: 'user already exists', insertedId: null });
        }

        // Set default role to 'user' if not specified
        const userData = { 
          ...user, 
          role: user.role || 'user', 
          createdAt: new Date(),
          status: 'active'
        };
        const result = await userCollection.insertOne(userData);
        res.send(result);
      } catch (err) {
        console.error("POST /users error:", err);
        res.status(500).send({ message: "Internal server error" });
      }
    });

    // Create admin user (special endpoint for first admin creation)
    app.post('/users/admin', async (req, res) => {
      try {
        const newUser = req.body;
        if (!newUser?.email) return res.status(400).send({ message: 'email required' });

        // Check if any admin exists
        const existingAdmin = await userCollection.findOne({ role: 'admin' });

        if (existingAdmin) {
          // If admin exists, require JWT token and admin privileges
          const authHeader = req.headers.authorization;
          if (!authHeader || !authHeader.startsWith("Bearer ")) {
            return res.status(401).send({ message: "Authentication required" });
          }

          const token = authHeader.split(" ")[1];
          try {
            const decoded = jwt.verify(token, JWT_SECRET);
            const requester = await userCollection.findOne({ email: decoded.email });
            
            if (!requester || requester.role !== 'admin') {
              return res.status(403).send({ message: 'Admin privileges required' });
            }
          } catch (error) {
            return res.status(401).send({ message: "Invalid token" });
          }
        }

        // Check if user already exists
        const existingUser = await userCollection.findOne({ email: newUser.email });
        if (existingUser) {
          // Update existing user to admin
          const result = await userCollection.updateOne(
            { email: newUser.email }, 
            { $set: { role: 'admin', updatedAt: new Date() } }
          );
          return res.send({ 
            acknowledged: result.acknowledged,
            modifiedCount: result.modifiedCount,
            message: 'User promoted to admin'
          });
        } else {
          // Insert new admin user
          const result = await userCollection.insertOne({
            ...newUser,
            role: 'admin',
            createdAt: new Date(),
            status: 'active'
          });
          return res.send({ 
            insertedId: result.insertedId,
            acknowledged: result.acknowledged,
            message: 'Admin user created successfully'
          });
        }
      } catch (err) {
        console.error("POST /users/admin error:", err);
        return res.status(500).send({ message: "Internal server error" });
      }
    });

    // Promote user to admin (admin only)
    app.patch('/users/admin/:id', verifyToken, async (req, res) => {
      const requesterIsAdmin = await checkIfRequesterIsAdmin(req);
      if (!requesterIsAdmin) return res.status(403).send({ message: 'forbidden access' });

      try {
        const id = req.params.id;
        const filter = { _id: new ObjectId(id) };
        const updatedDoc = { $set: { role: 'admin', updatedAt: new Date() } };
        const result = await userCollection.updateOne(filter, updatedDoc);
        res.send(result);
      } catch (error) {
        res.status(500).send({ message: "Error promoting user" });
      }
    });

    // Delete user (admin only)
    app.delete('/users/:id', verifyToken, async (req, res) => {
      const requesterIsAdmin = await checkIfRequesterIsAdmin(req);
      if (!requesterIsAdmin) return res.status(403).send({ message: 'forbidden access' });

      try {
        const id = req.params.id;
        const query = { _id: new ObjectId(id) };
        const result = await userCollection.deleteOne(query);
        res.send(result);
      } catch (error) {
        res.status(500).send({ message: "Error deleting user" });
      }
    });

    // Menu routes
    app.get('/menu', async (req, res) => {
      try {
        const result = await menuCollection.find().toArray();
        res.send(result);
      } catch (error) {
        res.status(500).send({ message: "Error fetching menu" });
      }
    });

    // Reviews routes
    app.get('/reviews', async (req, res) => {
      try {
        const result = await reviewsCollection.find().toArray();
        res.send(result);
      } catch (error) {
        res.status(500).send({ message: "Error fetching reviews" });
      }
    });

    // Cart routes
    app.get('/carts', async (req, res) => {
      try {
        const email = req.query.email;
        const query = email ? { email: email } : {};
        const result = await cartCollection.find(query).toArray();
        res.send(result);
      } catch (error) {
        res.status(500).send({ message: "Error fetching carts" });
      }
    });

    app.post('/carts', async (req, res) => {
      try {
        const cartItem = req.body;
        const result = await cartCollection.insertOne(cartItem);
        res.send(result);
      } catch (error) {
        res.status(500).send({ message: "Error adding to cart" });
      }
    });

    app.delete('/carts/:id', async (req, res) => {
      try {
        const id = req.params.id;
        const query = { _id: new ObjectId(id) };
        const result = await cartCollection.deleteOne(query);
        res.send(result);
      } catch (error) {
        res.status(500).send({ message: "Error deleting cart item" });
      }
    });

    console.log("All routes initialized successfully");

  } catch (error) {
    console.error("Failed to start server:", error);
  }
}

run().catch(console.dir);

app.listen(port, () => {
  console.log(`Server is running on port ${port}`);
});
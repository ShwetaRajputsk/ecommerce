# Authentication System - Complete Notes

## 📚 **Table of Contents**
1. [System Architecture Overview](#system-architecture-overview)
2. [Backend Components](#backend-components)
3. [Frontend Components](#frontend-components)
4. [Authentication Flow](#authentication-flow)
5. [Backend-Frontend Connection](#backend-frontend-connection)
6. [Security Features](#security-features)
7. [File Structure](#file-structure)

---

## 🏗️ **System Architecture Overview**

This is a **full-stack authentication system** with:
- **Frontend**: React + Vite + React Router
- **Backend**: Node.js + Express + MongoDB
- **Authentication**: JWT tokens stored in HTTP-only cookies
- **Database**: MongoDB with Mongoose ODM

**Key Technologies**:
- React 19.1.1, React Router DOM 7.8.0
- Node.js, Express 5.1.0, MongoDB 8.17.1
- JWT, bcryptjs, cookie-parser, CORS

---

## ⚙️ **Backend Components**

### **1. Server Setup (`backend/server.js`)**
```javascript
// Main server configuration
const app = express();

// CORS setup - allows frontend to communicate
app.use(cors({
  origin: 'http://localhost:5173',
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization']
}));

// Middleware
app.use(express.json());        // Parse JSON bodies
app.use(cookieParser());        // Parse cookies

// Database connection
mongoose.connect(process.env.MONGO_URI);

// Route mounting
app.use("/api", routes);        // All routes under /api
```

**Key Features**:
- CORS configuration for cross-origin requests
- Cookie parsing for JWT tokens
- MongoDB connection with environment variables
- Route mounting under `/api` prefix

### **2. User Model (`backend/models/User.js`)**
```javascript
const UserSchema = new mongoose.Schema({
  name: { type: String, required: true },
  email: { type: String, required: true, unique: true },
  password: { type: String, required: true },
}, { timestamps: true });
```

**Schema Fields**:
- `name`: User's display name
- `email`: Unique email address (used for login)
- `password`: Hashed password (never stored in plain text)
- `timestamps`: Automatic `createdAt` and `updatedAt`

### **3. Authentication Middleware (`backend/middleware/auth.js`)**
```javascript
module.exports = (req, res, next) => {
  // Extract token from cookie OR Authorization header
  const token = req.cookies?.token || 
                (req.header('Authorization') || '').replace('Bearer ', '');

  if (!token) return res.status(401).json({ message: 'No token, authorization denied' });

  try {
    // Verify JWT token
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    req.userId = decoded.id;  // Attach user ID to request
    next();
  } catch (err) {
    return res.status(401).json({ message: 'Token is not valid' });
  }
};
```

**Purpose**: Protects routes by validating JWT tokens
**Token Sources**: HTTP-only cookies (primary) or Authorization header (fallback)
**Output**: Attaches `req.userId` for route handlers to use

### **4. Authentication Routes (`backend/routes/auth.js`)**

#### **Signup Route (`POST /api/auth/signup`)**
```javascript
router.post('/signup', async (req, res) => {
  const { name, email, password } = req.body;
  
  // Validation
  if (!name || !email || !password) 
    return res.status(400).json({ message: 'All fields are required' });
  
  // Check existing user
  const existing = await User.findOne({ email });
  if (existing) return res.status(400).json({ message: 'User already exists' });
  
  // Hash password
  const salt = await bcrypt.genSalt(10);
  const hashed = await bcrypt.hash(password, salt);
  
  // Create user
  const user = new User({ name, email, password: hashed });
  await user.save();
  
  // Generate JWT
  const token = jwt.sign({ id: user._id }, process.env.JWT_SECRET, { expiresIn: '1h' });
  
  // Set HTTP-only cookie
  res.cookie('token', token, {
    httpOnly: true,
    secure: false,      // true in production
    sameSite: 'lax',
    maxAge: 1000 * 60 * 60, // 1 hour
  });
  
  res.status(201).json({ 
    message: 'User created', 
    user: { id: user._id, name: user.name, email: user.email } 
  });
});
```

#### **Login Route (`POST /api/auth/login`)**
```javascript
router.post('/login', async (req, res) => {
  const { email, password } = req.body;
  
  // Find user by email
  const user = await User.findOne({ email });
  if (!user) return res.status(400).json({ message: 'Invalid credentials' });
  
  // Verify password
  const isMatch = await bcrypt.compare(password, user.password);
  if (!isMatch) return res.status(400).json({ message: 'Invalid credentials' });
  
  // Generate JWT and set cookie (same as signup)
  const token = jwt.sign({ id: user._id }, process.env.JWT_SECRET, { expiresIn: '1h' });
  res.cookie('token', token, { /* same cookie options */ });
  
  res.json({ message: 'Logged in', user: { /* user data */ } });
});
```

#### **Protected Route (`GET /api/auth/me`)**
```javascript
router.get('/me', auth, async (req, res) => {
  try {
    // auth middleware provides req.userId
    const user = await User.findById(req.userId).select('-password');
    if (!user) return res.status(404).json({ message: 'User not found' });
    res.json({ user });
  } catch (err) {
    res.status(500).json({ message: 'Server error' });
  }
});
```

#### **Logout Route (`POST /api/auth/logout`)**
```javascript
router.post('/logout', (req, res) => {
  // Clear the token cookie
  res.clearCookie('token', { httpOnly: true, sameSite: 'lax' });
  res.json({ message: 'Logged out' });
});
```

---

## 🎨 **Frontend Components**

### **1. Main App (`frontend/src/App.jsx`)**
```javascript
import { Routes, Route, Link, Navigate } from 'react-router-dom';

export default function App() {
  return (
    <div style={{padding:20}}>
      <nav>
        <Link to="/signup">Signup</Link> | 
        <Link to="/login">Login</Link> | 
        <Link to="/dashboard">Dashboard</Link>
      </nav>

      <Routes>
        <Route path="/" element={<Navigate to="/login" />} />
        <Route path="/signup" element={<Signup/>} />
        <Route path="/login" element={<Login/>} />
        <Route path="/dashboard" element={
          <ProtectedRoute>
            <Dashboard/>
          </ProtectedRoute>
        } />
      </Routes>
    </div>
  );
}
```

**Routing Structure**:
- Root (`/`) → Redirects to `/login`
- `/signup` → Signup form
- `/login` → Login form  
- `/dashboard` → Protected dashboard (requires authentication)

### **2. API Service (`frontend/src/services/api.js`)**
```javascript
import axios from 'axios';

const api = axios.create({
  baseURL: 'http://localhost:5001/api', // Backend server address
  withCredentials: true, // Enable cookie sharing
});

export default api;
```

**Purpose**: Centralized HTTP client for all backend communication
**Key Features**:
- `baseURL`: Points to backend API
- `withCredentials`: Allows cookies to be sent/received

### **3. Protected Route Component (`frontend/src/components/ProtectedRoute.jsx`)**
```javascript
export default function ProtectedRoute({ children }){
  const [loading, setLoading] = useState(true);
  const [authed, setAuthed] = useState(false);

  useEffect(() => {
    // Check authentication status
    api.get('/auth/me')
      .then(res => setAuthed(true))
      .catch(err => setAuthed(false))
      .finally(() => setLoading(false));
  }, []);

  if (loading) return <div>Checking authentication...</div>;
  return authed ? children : <Navigate to="/login" />;
}
```

**Purpose**: Wraps components that require authentication
**Flow**: 
1. Makes API call to `/auth/me`
2. If successful → renders protected content
3. If failed → redirects to login

### **4. Authentication Pages**

#### **Signup Page (`frontend/src/pages/Signup.jsx`)**
```javascript
export default function Signup(){
  const [form, setForm] = useState({ name:'', email:'', password:'' });
  const [err, setErr] = useState('');
  const navigate = useNavigate();

  const handleSubmit = async (e) => {
    e.preventDefault();
    try {
      await api.post('/auth/signup', form); // Backend sets cookie
      navigate('/dashboard'); // Redirect on success
    } catch (error) {
      setErr(error?.response?.data?.message || 'Signup failed');
    }
  };

  return (
    <form onSubmit={handleSubmit}>
      <h2>Signup</h2>
      <input name="name" placeholder="Name" value={form.name} onChange={handleChange} />
      <input name="email" placeholder="Email" value={form.email} onChange={handleChange} />
      <input name="password" type="password" placeholder="Password" value={form.password} onChange={handleChange} />
      <button type="submit">Sign up</button>
      {err && <p style={{color:'red'}}>{err}</p>}
    </form>
  );
}
```

#### **Login Page (`frontend/src/pages/Login.jsx`)**
```javascript
export default function Login(){
  const [form, setForm] = useState({ email:'', password:'' });
  const [err, setErr] = useState('');
  const navigate = useNavigate();

  const handleSubmit = async (e) => {
    e.preventDefault();
    try {
      await api.post('/auth/login', form); // Backend sets cookie
      navigate('/dashboard'); // Redirect on success
    } catch (error) {
      setErr(error?.response?.data?.message || 'Login failed');
    }
  };

  return (
    <form onSubmit={handleSubmit}>
      <h2>Login</h2>
      <input name="email" placeholder="Email" value={form.email} onChange={handleChange} />
      <input name="password" type="password" placeholder="Password" value={form.password} onChange={handleChange} />
      <button type="submit">Log in</button>
      {err && <p style={{color:'red'}}>{err}</p>}
    </form>
  );
}
```

#### **Dashboard Page (`frontend/src/pages/Dashboard.jsx`)**
```javascript
export default function Dashboard(){
  const [user, setUser] = useState(null);
  const navigate = useNavigate();

  useEffect(() => {
    // Get user data
    api.get('/auth/me')
      .then(res => setUser(res.data.user))
      .catch(() => navigate('/login'));
  }, []);

  const logout = async () => {
    await api.post('/auth/logout'); // Clears cookie
    navigate('/login');
  };

  return (
    <div>
      <h2>Welcome {user.name}</h2>
      <p>{user.email}</p>
      <button onClick={logout}>Logout</button>
    </div>
  );
}
```

---

## 🔄 **Authentication Flow**

### **Complete User Journey**

#### **1. User Registration**
```
User fills signup form → Frontend sends POST /api/auth/signup → 
Backend validates data → Hashes password → Creates user → 
Generates JWT → Sets HTTP-only cookie → Returns success → 
Frontend redirects to dashboard
```

#### **2. User Login**
```
User fills login form → Frontend sends POST /api/auth/login → 
Backend finds user → Verifies password → Generates JWT → 
Sets HTTP-only cookie → Returns success → Frontend redirects to dashboard
```

#### **3. Accessing Protected Routes**
```
User visits /dashboard → ProtectedRoute component loads → 
Makes GET /api/auth/me request → Backend validates cookie → 
Returns user data → Component renders dashboard
```

#### **4. User Logout**
```
User clicks logout → Frontend sends POST /api/auth/logout → 
Backend clears cookie → Returns success → Frontend redirects to login
```

---

## 🔗 **Backend-Frontend Connection**

### **Connection Architecture**

The connection between frontend and backend is managed through several key files:

#### **1. Frontend API Service (`frontend/src/services/api.js`)**
```javascript
const api = axios.create({
  baseURL: 'http://localhost:5001/api', // 🔗 CONNECTION POINT
  withCredentials: true, // 🔑 ENABLES COOKIE SHARING
});
```

**Purpose**: This is the **main bridge** between frontend and backend. Every HTTP request goes through this file.

**Key Connection Features**:
- **`baseURL`**: Points to your backend server address
- **`withCredentials: true`**: Allows cookies to be sent/received between domains
- **`axios`**: HTTP client library that handles all API communication

#### **2. Backend CORS Configuration (`backend/server.js`)**
```javascript
app.use(cors({
  origin: 'http://localhost:5173',  // 🌐 ALLOWS FRONTEND ORIGIN
  credentials: true,                 // 🍪 ALLOWS COOKIE SHARING
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization']
}));
```

**Purpose**: Tells your backend to accept requests from your frontend domain.

**Key Points**:
- **`origin: 'http://localhost:5173'`**: Only your frontend can access the API
- **`credentials: true`**: Allows cookies to be sent between frontend and backend
- **Must be first middleware**: Applied before any routes

### **Connection Flow**

```
Frontend (Port 5173)                    Backend (Port 5001)
     │                                        │
     │ 1. User clicks "Sign Up"              │
     │                                        │
     │ 2. Component calls api.post()         │
     │                                        │
     │ 3. api.js adds baseURL                │
     │    http://localhost:5001/api          │
     │                                        │
     │ 4. Final URL:                          │
     │    http://localhost:5001/api/auth/signup │
     │                                        │
     │ 5. Request sent with cookies          │
     │    ┌─────────────────────────────────┐ │
     │    │ POST /api/auth/signup          │ │
     │    │ Origin: http://localhost:5173  │ │
     │    │ Cookie: token=abc123...        │ │
     │    └─────────────────────────────────┘ │
     │                                        │
     │ 6. CORS middleware checks origin      │
     │    ✅ Origin allowed                  │
     │    ✅ Credentials allowed             │
     │                                        │
     │ 7. Request routed to auth routes     │
     │    app.use("/api", routes)           │
     │    router.use("/auth", authRoutes)   │
     │                                        │
     │ 8. Handler processes request         │
     │    router.post('/signup', ...)      │
     │                                        │
     │ 9. Response sent back                │
     │    Set-Cookie: token=newToken        │
     │    { message: "User created" }      │
     │                                        │
     │ 10. Frontend receives response       │
     │     Cookie automatically stored       │
     │     User redirected to dashboard     │
```

### **Files That Handle Backend-Frontend Connection**

#### **Frontend Side:**
1. **`frontend/src/services/api.js`** - Main connection bridge
2. **`frontend/src/components/ProtectedRoute.jsx`** - Makes auth check requests
3. **`frontend/src/pages/Signup.jsx`** - Makes registration requests
4. **`frontend/src/pages/Login.jsx`** - Makes login requests
5. **`frontend/src/pages/Dashboard.jsx`** - Makes user data requests

#### **Backend Side:**
1. **`backend/server.js`** - CORS configuration and server setup
2. **`backend/index.js`** - Routes API requests to correct handlers
3. **`backend/routes/auth.js`** - Handles authentication requests
4. **`backend/middleware/auth.js`** - Protects routes and validates tokens

### **Configuration Requirements**

#### **1. Port Configuration**
- **Frontend**: Runs on port 5173 (Vite default)
- **Backend**: Runs on port 5001 (avoiding macOS ControlCenter conflict)
- **API Base URL**: `http://localhost:5001/api`

#### **2. CORS Settings**
- **Origin**: `http://localhost:5173` (your frontend)
- **Credentials**: `true` (for cookie sharing)
- **Methods**: GET, POST, PUT, DELETE, OPTIONS
- **Headers**: Content-Type, Authorization

#### **3. Cookie Configuration**
- **Domain**: localhost
- **Path**: /
- **HttpOnly**: true (security)
- **Secure**: false (for development)
- **SameSite**: lax (CSRF protection)

---

## 🔒 **Security Features**

### **1. Password Security**
- **Hashing**: Passwords are hashed using bcrypt with salt rounds of 10
- **Never Stored**: Plain text passwords are never stored in the database
- **Comparison**: Password verification uses `bcrypt.compare()` for secure comparison

### **2. JWT Security**
- **Secret Key**: JWT tokens are signed with a secret key stored in environment variables
- **Expiration**: Tokens expire after 1 hour for security
- **Payload**: Only contains user ID, no sensitive information

### **3. Cookie Security**
- **HttpOnly**: Cookies cannot be accessed by JavaScript (XSS protection)
- **SameSite**: Set to 'lax' for CSRF protection
- **Secure**: Set to false in development, should be true in production with HTTPS

### **4. Route Protection**
- **Middleware**: All protected routes use authentication middleware
- **Token Validation**: Every request to protected routes validates the JWT token
- **Automatic Redirect**: Unauthorized users are automatically redirected to login

---

## 📁 **File Structure**

```
Auth/
├── backend/
│   ├── index.js              # Route mounting
│   ├── server.js             # Main server + CORS + DB connection
│   ├── middleware/
│   │   └── auth.js          # JWT validation middleware
│   ├── models/
│   │   └── User.js          # MongoDB user schema
│   ├── routes/
│   │   └── auth.js          # Authentication endpoints
│   └── package.json         # Backend dependencies
└── frontend/
    ├── src/
    │   ├── App.jsx          # Main app + routing
    │   ├── main.jsx         # App entry point
    │   ├── components/
    │   │   └── ProtectedRoute.jsx  # Route protection
    │   ├── pages/
    │   │   ├── Dashboard.jsx       # Protected dashboard
    │   │   ├── Login.jsx           # Login form
    │   │   └── Signup.jsx          # Registration form
    │   ├── services/
    │   │   └── api.js              # Backend connection bridge
    │   └── index.css               # Global styles
    └── package.json         # Frontend dependencies
```

---

## 🚨 **Common Issues & Solutions**

### **1. CORS Errors**
```javascript
// Solution: Check CORS configuration in backend/server.js
app.use(cors({
  origin: 'http://localhost:5173',  // Must match your frontend URL
  credentials: true
}));
```

### **2. Port Conflicts**
```javascript
// Solution: Change backend port in server.js
const PORT = process.env.PORT || 5001; // Avoid port 5000 (macOS)
```

### **3. Cookie Not Sending**
```javascript
// Solution: Ensure withCredentials: true in frontend/api.js
const api = axios.create({
  baseURL: 'http://localhost:5001/api',
  withCredentials: true, // 🔑 This is crucial!
});
```

### **4. 401 Unauthorized Errors**
- **Normal behavior**: Protected routes return 401 when not authenticated
- **Solution**: User must login first to get valid JWT token
- **Flow**: 401 → Redirect to login → Login → Redirect to dashboard

---

## 📝 **Key Takeaways**

1. **`api.js`**: Frontend's connection bridge to backend
2. **`baseURL`**: Backend server address configuration
3. **`withCredentials`**: Enables cookie sharing between frontend and backend
4. **CORS**: Backend permission system for frontend access
5. **Port Configuration**: Frontend (5173) ↔ Backend (5001)
6. **Route Mapping**: `/api/*` → backend routes
7. **Cookie Sharing**: Authentication state between domains
8. **JWT Tokens**: Secure authentication mechanism
9. **HTTP-only Cookies**: XSS protection for tokens
10. **Protected Routes**: Automatic authentication checks

The system provides a **secure, scalable authentication solution** with proper separation of concerns between frontend and backend components!

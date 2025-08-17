# ServiceSwap

> A fully functional, real-time, geolocation-based service-for-service web platform.  
> Built with Flask, Socket.IO, SQLAlchemy, and semantic vector search in under 36 hours.

---

## ⚙️ Technical Architecture Overview

### Backend

- **Framework**: Flask  
- **Database**: SQLite (local) with SQLAlchemy ORM for abstraction  
- **Real-time Communication**: Flask-SocketIO for bidirectional WebSocket messaging  
- **Authentication**: Flask-Login for secure session-based auth  
- **Forms & Validation**: WTForms with CSRF protection and custom field validation  
- **Search Logic**: Semantic filtering powered by Sentence Transformers  

### Frontend

- **Styling**: TailwindCSS + custom CSS for responsive, mobile-first design  
- **Rendering**: Jinja2 templates dynamically populated from Flask  
- **Client Interactivity**: JavaScript for modals, chat windows, geolocation capture, and dynamic DOM updates  
- **Forms**: Custom error display with client-side validations layered on top of WTForms  

---

## 🧠 Key Technical Features

### 1. **Semantic Search Engine**

> `/utils/semantic_filter.py`

- Uses Sentence Transformers to encode all listing descriptions into high-dimensional vectors
- Incoming queries are transformed and compared via cosine similarity
- Returns sorted, contextually-relevant matches—even for loosely phrased inputs
- Vector math allows matching terms like "dog sitter" to "pet care" or "animal help"

### 2. **Geolocation-Based Listing Filtering**

> `HTML5 Geolocation API + Python Haversine`

- User coordinates captured on login via browser API  
- Listings are filtered using the Haversine distance formula on backend  
- Supports adjustable radius filtering (`5km`, `10km`, `Any Distance`)  
- Fully integrated into the listing search pipeline

### 3. **Real-Time Chat System**

> `/chat`, `/messages/<user_id>`

- WebSocket integration via Flask-SocketIO  
- Rooms created dynamically using user IDs  
- Persistent message history saved to SQLite  
- Asynchronous, bidirectional updates with message acknowledgment

### 4. **Modular Utility Layers**

- `semantic_filter.py`: Handles vectorization and cosine distance sorting
- `geo_filter.py`: (planned) future module to encapsulate all Haversine filtering
- `image_utils.py`: Handles profile picture uploads with type-checking and path consistency across listings/chat


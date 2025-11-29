// app.js — Complete IT Asset Management w/ RBAC
// app.js — Complete IT Asset Management w/ RBAC

const express = require('express');
const session = require('express-session');
const path = require('path');
const bodyParser = require('body-parser');
const sqlite3 = require('sqlite3').verbose();
const ExcelJS = require('exceljs');
const multer = require('multer');
const xlsx = require('xlsx');
const { DateTime } = require('luxon');

const app = express();
const aiRouter = require('./routes/ai'); // ✅ load route file

// ======================= DB Connection =======================
const dbPath = path.join(__dirname, 'it_asset.db');
const db = new sqlite3.Database(dbPath, sqlite3.OPEN_READWRITE, (err) => {
  if (err) console.error('❌ Failed to connect to SQLite DB:', err.message);
  else console.log('✅ Connected to SQLite DB');
});
// Optional: export db if needed in other modules
// module.exports = db;

// ======================= Middleware =======================
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(bodyParser.urlencoded({ extended: true }));

app.use(express.static('public'));
app.use(session({
  secret: 'it-asset-secure', // 🔒 Change to a more secure key in production
  resave: false,
  saveUninitialized: true
}));

const upload = multer({ dest: 'uploads/' });

// ======================= View Engine =======================
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));

// ======================= Global Helpers =======================


// ======================= Routes =======================
const aiRoute = require('./routes/ai');
app.use('/', aiRoute);

// ✅ You can register other routes here like:
// const assetRoutes = require('./routes/assets');
// app.use('/assets', assetRoutes);

// ======================= Root Redirect =======================
app.get('/', (req, res) => {
  res.redirect('/login');
});

// RBAC
function auth(req, res, next) {
  if (!req.session.user) return res.redirect('/login');
  next();
}
function onlyAdmin(req, res, next) {
  if (req.session.user.role === 'admin') return next();
  return res.status(403).render('403', { message: 'Admins only' });
}

// Audit logger


// Utility function in your app or separate module

// Require the utility function at the top of your file
 //const { toIST } = require('./utils'); // <-- Adjust path as needed

app.get('/audit-log', auth, onlyAdmin, (req, res) => {
  const institutionId = req.session.user.institution_id;

  const query = `
    SELECT 
      al.id,
      COALESCE(a.asset_id, 'DELETED') AS asset_tag,
      al.asset_id AS asset_db_id,
      al.action,
      al.performed_by,
      al.description,
      al.timestamp,
      i.full_name AS institution_name
    FROM 
      audit_logs al
    LEFT JOIN 
      assets a ON a.id = al.asset_id AND a.institution_id = ?
    LEFT JOIN 
      institutions i ON al.institution_id = i.id
    WHERE 
      al.institution_id = ?
    ORDER BY 
      al.id DESC
  `;

  db.all(query, [institutionId, institutionId], (err, rows) => {
    if (err) {
      console.error('❌ Audit log load error:', err.message);
      return res.status(500).send("Error loading audit logs");
    }
    db.get('SELECT full_name FROM institutions WHERE id = ?', [institutionId], (err2, inst) => {
      if (err2 || !inst) {
        console.error("❌ Failed to fetch institution name:", err2?.message);
        return res.status(500).send("Institution info not found");
      }
      res.render('audit-log', {
        logs: rows,
        toIST,  // Make sure your utils.js is correctly required, and this function always returns '—' for invalid input
        institutionName: inst.full_name,
        currentUser: req.session.user || { username: 'Guest', role: 'User' }
      });
    });
  });
});

// --- Authentication with Institution Selection ---

// Redirect root to login
app.get('/', (req, res) => res.redirect('/login'));

// GET: Show login form with institution list
app.get('/login', (req, res) => {
  const error = req.query.error || null;
  const message = req.query.message || null;

  db.all('SELECT * FROM institutions', [], (err, institutions) => {
    if (err) return res.status(500).send("Error loading institutions");

    res.render('login', {
      error: error,
      message: message, // ✅ Pass the message to the view
      institutions: institutions
    });
  });
});


// POST: Handle login with institution check
app.post('/login', (req, res) => {
  const { username, password, institution_id } = req.body;

  db.get(
    `SELECT * FROM users WHERE username = ? AND password = ? AND institution_id = ?`,
    [username, password, institution_id],
    (err, user) => {
      if (err) {
        console.error('Login error:', err.message);
        return res.send("❌ Internal server error during login.");
      }

      if (!user) {
        // Reload institution list and show error
        return db.all('SELECT * FROM institutions', (e2, institutions) => {
          if (e2) return res.send("❌ Error reloading institutions.");
          res.render('login', {
            error: '❌ Invalid username, password, or institution.',
            message: null,
            institutions
          });
        });
      }

      // ✅ Fetch institution name for logging
      db.get('SELECT name FROM institutions WHERE id = ?', [institution_id], (iErr, institution) => {
        if (iErr || !institution) {
          console.warn('Could not fetch institution name for audit log.');
        }

        // Save session
        req.session.user = user;
		// Clean and explicit currentUser session
req.session.user = {
  id: user.id,
  username: user.username,
  role: user.role,
  institution_id: user.institution_id
};
        req.session.institution_id = institution_id;

        // Log meaningful audit entry
        const institutionName = institution ? institution.name : `ID ${institution_id}`;
        logAudit(null, 'Login', user, `✅ User logged in from institution ${institutionName}`);

        if (institutionName === 'Admin') {
			
			
			
  res.redirect('/asset-summary');
} else {
  res.redirect('/dashboard');
}
      });
    }
  );
});



app.get('/logout', auth, (req, res) => {
  logAudit(null, 'Logout', req.session.user, 'User logged out');
  req.session.destroy(() => res.redirect('/login'));
});
// permissions.js
module.exports = {
  admin: [
    'AddAsset', 'EditAsset', 'TransferAsset', 'BulkUploader', 'MasterUpManagement',
    'Setting', 'AuditTrial', 'Report', 'preview', 'Sample', 'Logout' , 'Lifecycle'
  ],
  staff: [
    'AddAsset', 'EditAsset', 'TransferAsset', 'Setting', 'Report', 'Logout'
  ]
};




// --- Dashboard & Search ---
const permissions = require('./permissions'); // Make sure this is at the top of your file too

app.get('/dashboard', auth, (req, res) => {
  const currentUser = req.session.user;
  const query = req.query.query || '';
  const institutionId = currentUser.institution_id;
  const allowedModules = permissions[currentUser.role] || [];

  // First, get institution full name
  db.get('SELECT full_name FROM institutions WHERE id = ?', [institutionId], (err, institution) => {
    if (err || !institution) {
      console.error("Error fetching institution name:", err?.message);
      return res.status(500).send("Unable to load dashboard.");
    }

    // Now fetch asset records
  const sql = `SELECT * FROM assets WHERE institution_id = ?${query ? ' AND (serial_number LIKE ? OR asset_id LIKE ?)' : ''} LIMIT 4`;

    const params = query ? [institutionId, `%${query}%`, `%${query}%`] : [institutionId];

    db.all(sql, params, (err, records) => {
      if (err) {
        console.error("Dashboard query error:", err.message);
        return res.status(500).send("Error loading assets.");
      }

      res.render('dashboard', {
        records,
        query,
        currentUser,
        allowedModules,
        institutionName: institution.full_name  // ✅ Pass to EJS
      });
    });
  });
});


// ---- Settings ----
// GET: Change Password Page
app.get('/settings', (req, res) => {
  db.all('SELECT * FROM institutions', [], (err, institutions) => {
    if (err) {
      console.error('Error fetching institutions:', err.message);
      return res.status(500).send("Failed to load settings page.");
    }

    res.render('settings', {
      error: null,
      success: null,
      institutions
    });
  });
});


// POST: Handle Password Change
app.post('/settings', (req, res) => {
  const { institution_id, username, currentPassword, newPassword } = req.body;

  if (!institution_id || !username || !currentPassword || !newPassword) {
    db.all('SELECT * FROM institutions', [], (_, institutions) => {
      return res.render('settings', {
        error: '❌ All fields are required.',
        success: null,
        institutions
      });
    });
    return;
  }

  // Validate credentials
  db.get(
    `SELECT * FROM users WHERE username = ? AND password = ? AND institution_id = ?`,
    [username, currentPassword, institution_id],
    (err, user) => {
      if (err || !user) {
        db.all('SELECT * FROM institutions', [], (_, institutions) => {
          return res.render('settings', {
            error: '❌ Invalid username, password, or institution.',
            success: null,
            institutions
          });
        });
      } else {
        // Update password
        db.run(
          `UPDATE users SET password = ? WHERE id = ?`,
          [newPassword, user.id],
          (updateErr) => {
            if (updateErr) {
              db.all('SELECT * FROM institutions', [], (_, institutions) => {
                return res.render('settings', {
                  error: '⚠️ Failed to update password.',
                  success: null,
                  institutions
                });
              });
            } else {
              // Fetch institution name for audit log
              db.get(`SELECT name FROM institutions WHERE id = ?`, [institution_id], (instErr, inst) => {
                const instName = inst ? inst.name : `Institution ID ${institution_id}`;
                const detailMessage = `🔁 ${username} changed password for their account in ${instName}`;

                // ✅ Record audit trail
                logAudit(null, 'PasswordChange', username, detailMessage, institution_id);
              });

              // Log out and redirect with success
              req.session.destroy(() => {
                res.redirect('/login?message=✅ Password updated successfully! Please log in again.');
              });
            }
          }
        );
      }
    }
  );
});



// ---- Master Management (Admin only) ----
// ---- Master Management (Admin only) ----
app.get('/master-management', auth, onlyAdmin, (req, res) => {
  const currentUser = req.session.user;
  const institutionId = currentUser.institution_id;

  // Step 1: Fetch the institution's full name
  db.get('SELECT full_name FROM institutions WHERE id = ?', [institutionId], (err, institution) => {
    if (err || !institution) {
      console.error("Error fetching institution name:", err?.message);
      return res.status(500).send("Unable to load Master Management page.");
    }

    // Step 2: Render the Master Management page
    res.render('master-management', {
      institutionName: institution.full_name, // ✅ From DB (same as dashboard)
      currentUser                             // ✅ Includes username, role, etc.
    });
  });
});



// --- User Management ---
app.get('/users', auth, onlyAdmin, (req, res) => {
  const institutionId = req.session.user.institution_id;
  db.all('SELECT * FROM users WHERE institution_id = ?', [institutionId], (err, users) => {
    if (err) return res.status(500).send('Database error');
    res.render('masters/user-management', { users });
  });
});

app.get('/users/add', auth, onlyAdmin, (req, res) => {
  res.render('masters/add-user');
});

app.post('/users/add', auth, onlyAdmin, (req, res) => {
  const { username, email, password, role } = req.body;
  const institutionId = req.session.user.institution_id;

  db.run(
    'INSERT INTO users (username, email, password, role, institution_id) VALUES (?, ?, ?, ?, ?)',
    [username, email, password, role, institutionId],
    function (err) {
      if (err) return res.status(500).send('Database error');
      logAudit(null, 'User Added', req.session.user, `Created user "${username}" (${email}) with role "${role}" under institution ID ${institutionId}`);
      res.redirect('/users');
    }
  );
});

app.get('/users/delete/:id', auth, onlyAdmin, (req, res) => {
  const institutionId = req.session.user.institution_id;

  db.get('SELECT username, email FROM users WHERE id = ? AND institution_id = ?', [req.params.id, institutionId], (err, user) => {
    if (err || !user) return res.status(404).send('User not found or unauthorized');

    db.run('DELETE FROM users WHERE id = ? AND institution_id = ?', [req.params.id, institutionId], function (err2) {
      if (err2) return res.status(500).send('Delete failed');
      logAudit(null, 'User Deleted', req.session.user, `Deleted user "${user.username}" (${user.email}), ID ${req.params.id}`);
      res.redirect('/users');
    });
  });
});

app.post('/users/role/:id', auth, onlyAdmin, (req, res) => {
  const { role } = req.body;
  const institutionId = req.session.user.institution_id;

  db.get('SELECT username, role FROM users WHERE id = ? AND institution_id = ?', [req.params.id, institutionId], (err, user) => {
    if (err || !user) return res.status(404).send('User not found or unauthorized');

    db.run('UPDATE users SET role = ? WHERE id = ? AND institution_id = ?', [role, req.params.id, institutionId], function (err2) {
      if (err2) return res.status(500).send('Update failed');
      logAudit(null, 'User Role Updated', req.session.user, `Changed role of "${user.username}" from "${user.role}" to "${role}"`);
      res.redirect('/users');
    });
  });
});


// --- Department Management ---
app.get('/departments', auth, (req, res) => {
  db.all('SELECT * FROM departments', (err, departments) => {
    if (err) return res.status(500).send("DB error");
    res.render('masters/department', { departments });
  });
});
app.post('/departments', auth, (req, res) => {
  const { name } = req.body;
  db.run('INSERT INTO departments (name) VALUES (?)', [name], function(err) {
    if (err) return res.status(500).send("Insert failed");
    logAudit(null, 'Add Department', req.session.user, `Added department: ${name}`);
    res.redirect('/departments');
  });
});
app.get('/department/delete/:id', auth, (req, res) => {
  db.get('SELECT name FROM departments WHERE id = ?', [req.params.id], (err, dept) => {
    if (err || !dept) return res.status(500).send('Department not found');
    db.run('DELETE FROM departments WHERE id = ?', [req.params.id], function(err2) {
      if (err2) return res.status(500).send('Delete failed');
      logAudit(null, 'Delete Department', req.session.user, `Deleted department: ${dept.name} (id: ${req.params.id})`);
      res.redirect('/departments');
    });
  });
});
app.post('/department/add', auth, (req, res) => {
  const { name } = req.body;
  db.run('INSERT INTO departments (name) VALUES (?)', [name], function(err) {
    if (err) return res.status(500).send('Insert failed');
    logAudit(null, 'Add Department', req.session.user, `Added department: ${name}`);
    res.redirect('/departments');
  });
});

// --- Department Management (Scoped by institution_id) ---
app.get('/departments', auth, (req, res) => {
  const institutionId = req.session.user.institution_id;

  db.all('SELECT * FROM departments WHERE institution_id = ?', [institutionId], (err, departments) => {
    if (err) return res.status(500).send("DB error");
    res.render('masters/department', { departments });
  });
});

// POST: Add new department (from main form)
app.post('/departments', auth, (req, res) => {
  const { name } = req.body;
  const institutionId = req.session.user.institution_id;

  db.run('INSERT INTO departments (name, institution_id) VALUES (?, ?)', [name, institutionId], function(err) {
    if (err) return res.status(500).send("Insert failed");
    logAudit(null, 'Add Department', req.session.user, `Created department "${name}" under institution ID ${institutionId}`);
    res.redirect('/departments');
  });
});

// GET: Delete department
app.get('/department/delete/:id', auth, (req, res) => {
  const institutionId = req.session.user.institution_id;

  db.get('SELECT name FROM departments WHERE id = ? AND institution_id = ?', [req.params.id, institutionId], (err, dept) => {
    if (err || !dept) return res.status(404).send('Department not found or unauthorized');
    
    db.run('DELETE FROM departments WHERE id = ? AND institution_id = ?', [req.params.id, institutionId], function(err2) {
      if (err2) return res.status(500).send('Delete failed');
      logAudit(null, 'Delete Department', req.session.user, `Deleted department "${dept.name}" (ID: ${req.params.id}) from institution ID ${institutionId}`);
      res.redirect('/departments');
    });
  });
});

// POST: Add department from alternate form (redundant, but kept)
app.post('/department/add', auth, (req, res) => {
  const { name } = req.body;
  const institutionId = req.session.user.institution_id;

  db.run('INSERT INTO departments (name, institution_id) VALUES (?, ?)', [name, institutionId], function(err) {
    if (err) return res.status(500).send('Insert failed');
    logAudit(null, 'Add Department', req.session.user, `Created department "${name}" under institution ID ${institutionId}`);
    res.redirect('/departments');
  });
});


// --- Location Management (Institution Scoped) ---
app.get('/locations', auth, (req, res) => {
  const institutionId = req.session.user.institution_id;

  db.all(
    'SELECT * FROM locations WHERE institution_id = ? ORDER BY floor, location_name',
    [institutionId],
    (err, locations) => {
      if (err) return res.status(500).send("DB error");
      res.render('masters/location-management', { locations });
    }
  );
});

// POST: Add location
app.post('/locations', auth, (req, res) => {
  const { floor, location_name } = req.body;
  const institutionId = req.session.user.institution_id;

  db.run(
    'INSERT INTO locations (floor, location_name, institution_id) VALUES (?, ?, ?)',
    [floor, location_name, institutionId],
    function (err) {
      if (err) return res.status(500).send("Insert failed");
      logAudit(null, 'Add Location', req.session.user, `Created location: ${floor} - ${location_name} (Institution ID: ${institutionId})`);
      res.redirect('/locations');
    }
  );
});

// GET: Delete location securely
app.get('/location/delete/:id', auth, (req, res) => {
  const { id } = req.params;
  const institutionId = req.session.user.institution_id;

  db.get('SELECT * FROM locations WHERE id = ? AND institution_id = ?', [id, institutionId], (err, loc) => {
    if (err || !loc) return res.status(404).send('Location not found or not authorized');

    db.run('DELETE FROM locations WHERE id = ? AND institution_id = ?', [id, institutionId], function (err2) {
      if (err2) return res.status(500).send("Delete failed");
      logAudit(null, 'Delete Location', req.session.user, `Deleted location: ${loc.floor} - ${loc.location_name} (ID: ${id}, Institution ID: ${institutionId})`);
      res.redirect('/locations');
    });
  });
});

// --- Alternate Page: Manage Locations ---
app.get('/manage-locations', auth, (req, res) => {
  const institutionId = req.session.user.institution_id;

  db.all("SELECT * FROM locations WHERE institution_id = ? ORDER BY floor, location_name", [institutionId], (err, locations) => {
    if (err) return res.status(500).send("Error loading locations");
    res.render('masters/location-management', { locations });
  });
});

// POST: Add Location (alternate route)
app.post('/add-location', auth, (req, res) => {
  const { floor, location_name } = req.body;
  const institutionId = req.session.user.institution_id;

  db.run(
    'INSERT INTO locations (floor, location_name, institution_id) VALUES (?, ?, ?)',
    [floor, location_name, institutionId],
    function (err) {
      if (err) return res.status(500).send('Insert failed');
      logAudit(null, 'Add Location', req.session.user, `Created location: ${floor} - ${location_name} (Institution ID: ${institutionId})`);
      res.redirect('/locations');
    }
  );
});

// DELETE: Alternate Delete Location (with secure check)
app.get('/delete-location/:id', auth, (req, res) => {
  const id = req.params.id;
  const institutionId = req.session.user.institution_id;

  db.get("SELECT * FROM locations WHERE id = ? AND institution_id = ?", [id, institutionId], (err, loc) => {
    if (err || !loc) return res.status(404).send("Not found or unauthorized");

    db.run("DELETE FROM locations WHERE id = ? AND institution_id = ?", [id, institutionId], err2 => {
      if (!err2)
        logAudit(null, 'Delete Location', req.session.user, `Deleted location: ${loc.floor} - ${loc.location_name} (ID: ${id}, Institution ID: ${institutionId})`);
      if (err2) return res.status(500).send("Delete failed");
      res.redirect('/manage-locations');
    });
  });
});

// --- Institution-Based Custom Model Management ---
app.get('/manage-models', auth, (req, res) => {
  const institutionId = req.session.user.institution_id;

  db.all("SELECT * FROM models WHERE institution_id = ?", [institutionId], (err, models) => {
    if (err) return res.status(500).send("Error loading models");
    res.render('masters/model-management', { models });
  });
});

app.post('/add-model', auth, (req, res) => {
  const { model_name, category } = req.body;
  const institutionId = req.session.user.institution_id;

  db.run(
    "INSERT INTO models (model_name, category, institution_id) VALUES (?, ?, ?)",
    [model_name, category, institutionId],
    function(err) {
      if (err) return res.status(500).send("Insert failed");
      logAudit(null, 'Add Model', req.session.user, `Added model: ${model_name} (${category}) for institution ID ${institutionId}`);
      res.redirect('/manage-models');
    }
  );
});

app.get('/delete-model/:id', auth, (req, res) => {
  const modelId = req.params.id;
  const institutionId = req.session.user.institution_id;

  db.get("SELECT * FROM models WHERE id = ? AND institution_id = ?", [modelId, institutionId], (err, model) => {
    if (err || !model) return res.status(404).send("Model not found or not authorized");

    db.run("DELETE FROM models WHERE id = ? AND institution_id = ?", [modelId, institutionId], function(err2) {
      if (err2) return res.status(500).send("Delete failed");
      logAudit(null, 'Delete Model', req.session.user, `Deleted model: ${model.model_name} (${model.category}), ID: ${modelId}, Institution ID: ${institutionId}`);
      res.redirect('/manage-models');
    });
  });
});


function logAudit(assetId, action, user, description) {
  const institutionId = user.institution_id;
  const stmt = db.prepare(`
    INSERT INTO audit_logs (timestamp, user_id, username, role, action, asset_id, description, institution_id)
    VALUES (datetime('now', 'localtime'), ?, ?, ?, ?, ?, ?, ?)
  `);
  stmt.run(user.id, user.username, user.role, action, assetId, description, institutionId);
}

// ---- Condemned Assets View (Institution-Specific) ----
app.get('/condemned', auth, onlyAdmin, (req, res) => {
  const currentUser = req.session.user;
  const institutionId = currentUser.institution_id;

  // Fetch institution full name from DB
  db.get('SELECT full_name FROM institutions WHERE id = ?', [institutionId], (err, institution) => {
    if (err || !institution) {
      console.error("❌ Error fetching institution name:", err?.message);
      return res.status(500).send("Unable to load condemned assets.");
    }

    // Now fetch condemned assets
    const sql = `
      SELECT * 
      FROM assets 
      WHERE status = 'condemned' 
      AND institution_id = ? 
      ORDER BY invoice_date DESC
    `;

    db.all(sql, [institutionId], (err2, assets) => {
      if (err2) {
        console.error("❌ Error fetching condemned assets:", err2.message);
        return res.status(500).send("Failed to load condemned assets.");
      }

      // Render EJS page with all info
      res.render('condemned', {
        assets,
        institutionName: institution.full_name,  // ✅ Pass institution name
        currentUser: {
          username: currentUser.username,
          role: currentUser.role
        }
      });
    });
  });
});


// ---- Export Condemned Assets (Institution-Specific) ----
app.get('/export-condemned', auth, onlyAdmin, (req, res) => {
  const institutionId = req.session.user.institution_id;

  db.all(
    "SELECT * FROM assets WHERE status='condemned' AND institution_id = ?",
    [institutionId],
    async (err, rows) => {
      if (err) return res.status(500).send("Failed to fetch condemned assets");

      const ExcelJS = require('exceljs');
      const workbook = new ExcelJS.Workbook();
      const worksheet = workbook.addWorksheet("Condemned Assets");

      if (rows.length > 0) {
        worksheet.columns = Object.keys(rows[0]).map(key => ({
          header: key.toUpperCase(),
          key: key
        }));
        rows.forEach(row => worksheet.addRow(row));
      }

      res.setHeader('Content-Disposition', 'attachment; filename=condemned_assets.xlsx');
      res.setHeader('Content-Type', 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet');
      await workbook.xlsx.write(res);

      logAudit(null, 'Export Condemned Assets', req.session.user, 'Exported condemned asset list');
    }
  );
});

// GET: Show Bulk Upload Form


// GET: Bulk Upload Form Page
app.get('/bulk-upload', auth, onlyAdmin, (req, res) => {
  const institution_id = req.session.user.institution_id;

  db.get('SELECT full_name FROM institutions WHERE id = ?', [institution_id], (err, institution) => {
    if (err || !institution) {
      console.error("Error fetching institution name:", err?.message);
      return res.status(500).send("Unable to load upload form.");
    }

    res.render('upload', {
      institutionName: institution.full_name,
      currentUser: req.session.user || { username: 'Guest', role: 'User' },
      message: null
    });
  });
});

// POST: Handle Excel Upload
app.post('/upload-assets', auth, onlyAdmin, upload.single('excelFile'), (req, res) => {
  try {
    const filePath = req.file.path;
    const workbook = xlsx.readFile(filePath);
    const sheet = workbook.Sheets[workbook.SheetNames[0]];
    const rows = xlsx.utils.sheet_to_json(sheet);
    const institution_id = req.session.user.institution_id;

    if (!rows || rows.length === 0) {
      return res.render('upload', {
        institutionName: req.session.user.institution_name,
        currentUser: req.session.user,
        message: '❌ Excel file is empty or invalid format.'
      });
    }

    db.serialize(() => {
 const stmt = db.prepare(`
  INSERT INTO assets (
    id,
    asset_type, item_category, item_sub_category, serial_number, asset_id,
    model_name, user_name, processor, location, speed,
    hdd, monitor, ram, ip_address, mac_address,
    warranty, switch_port, switch_ip, port_mark, order_no,
    order_date, doi, invoice_no, invoice_date, cost,
    supplier, ssd, amc, remarks, department,
    status, system_type, pc, pc_type, printer_ip_address,
    amc_warranty, switch_port_no, switch_ip_address, institution_id
  ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
`);


      let failedRows = [];

      for (const row of rows) {
        try {
          stmt.run([
  row['ID'], // ← insert this at the beginning if you're inserting id manually
  row['Asset Type'], row['Item Category'], row['Item Sub Category'], row['Serial No'], row['Asset ID'],
  row['Model Name'], row['User Name'], row['Processor'], row['Location'], row['Speed'],
  row['HDD'], row['Monitor'], row['RAM'], row['IP Address'], row['MAC Address'],
  row['Warranty'], row['Switch Port'], row['Switch IP'], row['Port Mark'], row['Order No'],
  row['Order Date'], row['DOI'], row['Invoice No'], row['Invoice Date'], row['Cost'],
  row['Supplier'], row['SSD'], row['AMC'], row['Remarks'], row['Department'],
  row['Status'], row['System Type'], row['PC'], row['PC Type'], row['Printer IP Address'],
  row['AMC/Warranty'], row['Switch Port No'], row['Switch IP Address'], institution_id
]);

        } catch (err) {
          if (err.message.includes('UNIQUE constraint')) {
            failedRows.push(row['Asset ID'] || row['Serial No']);
          } else {
            console.error("Upload error:", err.message);
            return res.render('upload', {
              institutionName: req.session.user.institution_name,
              currentUser: req.session.user,
              message: '❌ Upload failed: ' + err.message
            });
          }
        }
      }

      stmt.finalize(() => {
        if (failedRows.length > 0) {
          return res.render('upload', {
            institutionName: req.session.user.institution_name,
            currentUser: req.session.user,
            message: `❌ Duplicate found for ${failedRows.length} item(s): ${failedRows.join(', ')}`
          });
        }

        // Audit log
        logAudit(
          null,
          'Bulk Upload',
          req.session.user,
          `Assets uploaded in bulk by ${req.session.user.username} (Institution: ${req.session.user.institution_name})`
        );

        res.render('upload', {
          institutionName: req.session.user.institution_name,
          currentUser: req.session.user,
          message: '✅ Bulk upload completed'
        });
      });
    });
  } catch (error) {
    console.error('❌ Unexpected error during upload:', error.message);
    res.render('upload', {
      institutionName: req.session.user.institution_name,
      currentUser: req.session.user,
      message: '❌ Internal server error during upload.'
    });
  }
});

// GET: Download Excel Template (MUST add this!)
app.get('/download-template', auth, (req, res) => {
  const filePath = path.join(__dirname, 'uploads', 'asset_template.xlsx');
  console.log("Serving download:", filePath);
  res.download(filePath, 'IT_Asset_Upload_Template.xlsx', err => {
    if (err) {
      console.error('❌ Download error:', err.message);
      res.status(500).send('File not found or error downloading.');
    }
  });
});



// ✅ GET + POST: Add Asset for Institution
app.route('/add-asset')
  .get(auth, (req, res) => {
    const institution_id = req.session.user.institution_id;
    const success = req.query.success === '1';

    db.get('SELECT full_name FROM institutions WHERE id = ?', [institution_id], (err, institution) => {
      if (err || !institution) {
        console.error("Error fetching institution name:", err?.message);
        return res.status(500).send("Unable to load dashboard.");
      }

      db.all("SELECT * FROM departments WHERE institution_id = ?", [institution_id], (err1, departments) => {
        if (err1) return res.status(500).send('Error loading departments');

        db.all("SELECT * FROM models WHERE institution_id = ?", [institution_id], (err2, models) => {
          if (err2) return res.status(500).send('Error loading models');

          db.all("SELECT * FROM locations WHERE institution_id = ? ORDER BY floor, location_name", [institution_id], (err3, locations) => {
            if (err3) return res.status(500).send('Error loading locations');

            res.render('add_asset', {
              institutionName: institution.full_name,
              currentUser: req.session.user || { username: 'Guest', role: 'User' },
              departments,
              models,
              locations,
              success,
              error: null,
              formData: {}
            });
          });
        });
      });
    });
  })

  .post(auth, (req, res) => {
    const formData = req.body;
    const institution_id = req.session.user.institution_id;
    const { serial_number, asset_id } = formData;

    // ✅ Define assetFields here
const assetFields = [
  "asset_type", "item_category", "item_sub_category", "serial_number", "asset_id",
  "model_name", "user_name", "processor", "location", "speed", "hdd", "monitor", "ram",
  "ip_address", "mac_address", "warranty", "switch_port", "switch_ip", "port_mark",
  "order_no", "order_date", "doi", "invoice_no", "invoice_date", "cost", "supplier",
  "ssd", "amc", "remarks", "department", "status", "system_type", "pc", "pc_type",
  "printer_ip_address", "amc_warranty", "switch_port_no", "switch_ip_address"
];


    const checkQuery = `
      SELECT * FROM assets WHERE (asset_id = ? OR serial_number = ?) AND institution_id = ?
    `;

    db.get(checkQuery, [asset_id, serial_number, institution_id], (err, existingAsset) => {
      if (err) return res.status(500).send('❌ Error checking for existing asset.');

      if (existingAsset) {
        // If duplicate asset found, reload form with error
        db.all("SELECT * FROM departments WHERE institution_id = ?", [institution_id], (err1, departments) => {
          db.all("SELECT * FROM models WHERE institution_id = ?", [institution_id], (err2, models) => {
            db.all("SELECT * FROM locations WHERE institution_id = ? ORDER BY floor, location_name", [institution_id], (err3, locations) => {
              return res.render('add_asset', {
                departments,
                models,
                locations,
                success: false,
                error: '❌ Asset with same Asset ID or Serial Number already exists.',
                formData
              });
            });
          });
        });
      } else {
const values = assetFields.map(f => formData[f] || '');
values.push(institution_id); // For the institution_id column

const insertQuery = `
  INSERT INTO assets (${[...assetFields, 'institution_id'].join(',')})
  VALUES (${[...assetFields, 'institution_id'].map(() => '?').join(',')})
`;
        db.run(insertQuery, values, function (insertErr) {
          if (insertErr) {
            console.error('❌ Insert error:', insertErr.message);
            return res.status(500).send('❌ Failed to insert asset.');
          }

          // ✅ Audit Log
          logAudit(
            asset_id,
            'Add Asset',
            req.session.user,
            `New asset added by ${req.session.user.username} for institution ${institution_id}`
          );

          // ✅ Redirect with success
          res.redirect('/add-asset?success=1');
        });
      }
    });
  });


//edit asset
app.get('/edit-asset', auth, (req, res) => {
  const { query, department } = req.query;
  const institution_id = req.session.user.institution_id;
  const institutionName = req.session.user.institution_name; // ✅ Get from session
  const currentUser = req.session.user; // ✅ Get current user object

  let sql = 'SELECT * FROM assets WHERE institution_id = ?';
  let params = [institution_id];

  if (query) {
    sql += ' AND (serial_number LIKE ? OR asset_id LIKE ?)';
    params.push(`%${query}%`, `%${query}%`);
  }

  if (department) {
    sql += ' AND department = ?';
    params.push(department);
  }

  sql += ' ORDER BY id DESC';

  db.all(sql, params, (err, rows) => {
    if (err) {
      console.error('❌ Error fetching assets:', err.message);
      return res.status(500).send('❌ Error fetching assets');
    }

    db.all('SELECT name FROM departments WHERE institution_id = ?', [institution_id], (dErr, departments) => {
      if (dErr) {
        console.error('❌ Error loading departments:', dErr.message);
        return res.status(500).send('❌ Error loading departments.');
      }

      res.render('edit-asset', {
        records: rows,
        departments,
        query,
        department,
        institutionName,   // ✅ Pass institution name to EJS
        currentUser        // ✅ Pass entire user object to EJS
      });
    });
  });
});


	app.get('/edit-form/:id', auth, (req, res) => {
  const assetId = req.params.id;
  const institution_id = req.session.user.institution_id;

  db.get('SELECT * FROM assets WHERE id = ? AND institution_id = ?', [assetId, institution_id], (e1, asset) => {
    if (e1 || !asset) return res.send('❌ Asset not found or access denied.');

    db.all('SELECT name FROM departments WHERE institution_id = ?', [institution_id], (e2, departments) => {
      if (e2) return res.send('❌ Error loading departments.');

      db.all('SELECT model_name FROM models WHERE institution_id = ?', [institution_id], (e3, models) => {
        if (e3) return res.send('❌ Error loading models.');

        db.all('SELECT * FROM locations WHERE institution_id = ?', [institution_id], (e4, locations) => {
          if (e4) return res.send('❌ Error loading locations.');

          res.render('edit-form', {
            asset,
            departments,
            models,
            locations
          });
        });
      });
    });
  });
});


// View All Assets Route
app.get('/assets', (req, res) => {
  const institutionId = req.session.user?.institution_id;

  if (!institutionId) {
    return res.redirect('/login'); // or show error
  }

  db.all('SELECT * FROM assets WHERE institution_id = ?', [institutionId], (err, assets) => {
    if (err) {
      console.error(err);
      return res.status(500).send('Database error');
    }

    res.render('assets', { assets, institutionName: req.session.user.institution_name });
  });
});


// POST: Update Asset
app.post('/update/:id', (req, res) => {
  const assetId = req.params.id;
  const formData = req.body;
  const user = req.session.user;

  // Fields allowed for comparison/update (asset_id excluded)
  const fields = [
    "asset_type", "item_category", "item_sub_category", "serial_number",
    "model_name", "user_name", "processor", "location", "speed",
    "hdd", "monitor", "ram", "ip_address", "mac_address", "warranty",
    "switch_port", "switch_ip", "port_mark", "order_no", "order_date", "doi",
    "invoice_no", "invoice_date", "cost", "supplier", "ssd", "amc", "remarks",
    "department", "status", "system_type", "pc", "pc_type", "printer_ip_address",
    "amc_warranty", "switch_port_no", "switch_ip_address"
  ];

  // Fetch current asset from DB
  db.get('SELECT * FROM assets WHERE id = ?', [assetId], (err, existingAsset) => {
    if (err || !existingAsset) {
      console.error("❌ Asset not found or DB error:", err);
      return res.status(500).send('❌ Asset not found');
    }

    // Protect asset_id from being altered
    if (formData.asset_id && formData.asset_id !== existingAsset.asset_id) {
      return res.status(400).send('❌ Asset ID mismatch. Update not allowed.');
    }

    const updatedFields = [];
const values = [];
const auditLogs = [];
const now = new Date(); // Only create Date once!
const nowISO = now.toISOString(); // Store in DB
const nowIST = now.toLocaleString('en-IN', {
  timeZone: 'Asia/Kolkata',
  dateStyle: 'medium',
  timeStyle: 'short'
});

fields.forEach(field => {
  const oldVal = (existingAsset[field] ?? '').toString().trim();
  const newVal = (formData[field] ?? '').toString().trim();

  // Only update if value has changed and newVal is not empty
  if (newVal && oldVal !== newVal) {
    updatedFields.push(`${field} = ?`);
    values.push(newVal);

    auditLogs.push({
      asset_id: assetId,
      action: 'Asset Update',
      performed_by: user.username,
      department: existingAsset.department,
      description: `${field.toUpperCase()} changed from "${oldVal}" to "${newVal}" on ${nowIST} by ${user.role} (${user.username})`,
      timestamp: nowISO,            // ALWAYS ISO in DB
      user_id: user.id,
      institution_id: user.institution_id
      // Remove username & role if unnecessary (performed_by already set)
    });
  }
});


    // If nothing changed
    if (updatedFields.length === 0) {
      return res.redirect('/assets');
    }

    // Final SQL update
    const updateSQL = `UPDATE assets SET ${updatedFields.join(', ')} WHERE id = ?`;
    values.push(assetId);

    db.run(updateSQL, values, function (updateErr) {
      if (updateErr) {
        console.error("❌ Update failed:", updateErr);
        return res.status(500).send('❌ Update failed');
      }

      // Prepare audit insert
      const insertAudit = db.prepare(`
        INSERT INTO audit_logs 
        (asset_id, action, performed_by, department, description, timestamp, user_id, username, role, institution_id)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
      `);

      auditLogs.forEach(log => {
        insertAudit.run(
          log.asset_id,
          log.action,
          log.performed_by,
          log.department,
          log.description,
          log.timestamp,
          log.user_id,
          log.username,
          log.role,
          log.institution_id
        );
      });

      insertAudit.finalize(() => {
        res.redirect('/assets');
      });
    });
  });
});

app.get('/delete/:id', auth, onlyAdmin, (req, res) => {
  const assetId = req.params.id;
  const institutionId = req.session.user.institution_id;

  // Step 1: Fetch asset and validate ownership
  db.get(
    'SELECT asset_id, model_name, serial_number, institution_id FROM assets WHERE id = ?',
    [assetId],
    (err, asset) => {
      if (err || !asset) {
        return res.status(404).send("❌ Asset not found.");
      }

      // Step 2: Ownership check
      if (asset.institution_id !== institutionId) {
        return res.status(403).send("❌ You are not authorized to delete this asset.");
      }

      // Step 3: Proceed with delete
      db.run('DELETE FROM assets WHERE id = ?', [assetId], (delErr) => {
        if (delErr) {
          return res.status(500).send("❌ Delete failed.");
        }

        // Step 4: Audit log
        logAudit(
          asset.asset_id,
          'Asset Deleted',
          req.session.user,
          `Deleted ${asset.model_name} (${asset.serial_number}) from institution ID: ${institutionId}`
        );

        res.redirect('/edit-asset');
      });
    }
  );
});

// GET: Show all assets for transfer (institution-wise)
// GET: Show list of assets for transfer (Institution-wise)
app.get('/transfer-asset', auth, (req, res) => {
  const q = req.query.query?.trim().toLowerCase() || '';
  const department = req.query.department || '';
  const institutionId = req.session.user.institution_id;

  let sql = 'SELECT * FROM assets WHERE institution_id = ?';
  const params = [institutionId];

  if (q) {
    sql += ' AND (LOWER(serial_number) LIKE ? OR LOWER(asset_id) LIKE ?)';
    params.push(`%${q}%`, `%${q}%`);
  }

  if (department) {
    sql += ' AND department = ?';
    params.push(department);
  }

  sql += ' ORDER BY id DESC';

  db.all(sql, params, (err, records) => {
    if (err) {
      console.error('❌ Error loading assets:', err.message);
      return res.status(500).send('Database error');
    }

    db.all('SELECT name FROM departments WHERE institution_id = ?', [institutionId], (dErr, departments) => {
      if (dErr) {
        console.error('❌ Error loading departments:', dErr.message);
        return res.status(500).send('Department load error');
      }

      db.get('SELECT full_name FROM institutions WHERE id = ?', [institutionId], (iErr, institution) => {
        if (iErr || !institution) {
          console.error('❌ Institution fetch error:', iErr?.message);
          return res.status(500).send('Institution not found');
        }

        res.render('transfer-asset', {
          institutionName: institution.full_name,      // ✅ needed for sticky header
          currentUser: req.session.user,              // ✅ needed for sticky header
          records,
          departments,
          query: q,
          department
        });
      });
    });
  });
});

app.get('/transfer-form/:id', auth, (req, res) => {
  const assetId = req.params.id;
  const institutionId = req.session.user.institution_id;

  db.get('SELECT * FROM assets WHERE id = ? AND institution_id = ?', [assetId, institutionId], (err, asset) => {
    if (err) {
      console.error('❌ Error fetching asset:', err.message);
      return res.status(500).send('Error fetching asset');
    }

    if (!asset) {
      return res.status(404).send('❌ Asset not found or access denied');
    }

    db.all('SELECT name FROM departments WHERE institution_id = ?', [institutionId], (dErr, departments) => {
      if (dErr) {
        console.error('❌ Error loading departments:', dErr.message);
        return res.status(500).send('Error loading departments');
      }

      db.all('SELECT location_name FROM locations WHERE institution_id = ?', [institutionId], (lErr, locations) => {
        if (lErr) {
          console.error('❌ Error loading locations:', lErr.message);
          return res.status(500).send('Error loading locations');
        }

        // 🔧 Add institutionName & currentUser
        db.get('SELECT full_name FROM institutions WHERE id = ?', [institutionId], (iErr, institution) => {
          if (iErr || !institution) {
            console.error('❌ Error loading institution name:', iErr?.message);
            return res.status(500).send('Error loading institution info');
          }

     res.render('transfer-form', {
  asset,
  departments,
  locations,
  institutionName: institution.full_name,
  currentUser: req.session.user,
  query: {
    success: req.query.success,
    error: req.query.error
  }
});
        });
      });
    });
  });
});

// POST: Handle Transfer
app.post('/transfer-form/:id', auth, (req, res) => {
  const assetId = req.params.id;
  const institutionId = req.session.user.institution_id;
  const { actionType, department, location, user_name, remarks } = req.body;

  // 🔒 Validate remark
  if (!remarks || remarks.trim() === '') {
    return res.redirect(`/transfer-form/${assetId}?error=remark`);
  }

  if (actionType === 'transfer') {
    // 🔒 Validate department and location
    if (!department || !location) {
      return res.redirect(`/transfer-form/${assetId}?error=missing`);
    }

    const updateSql = `
      UPDATE assets 
      SET department = ?, location = ?, user_name = ?, status = 'active', remarks = ?
      WHERE id = ? AND institution_id = ?
    `;

    db.run(updateSql, [department, location, user_name || '', remarks, assetId, institutionId], function (err) {
      if (err) {
        console.error('❌ Transfer update error:', err.message);
        return res.status(500).send('❌ Database error during transfer.');
      }

      if (this.changes === 0) {
        return res.redirect(`/transfer-form/${assetId}?error=nochange`);
      }

      const description = `Transferred to Dept: ${department}, Location: ${location}, User: ${user_name || 'N/A'}, Remark: ${remarks}`;
      logAudit(assetId, 'Transfer Asset', req.session.user, description);

      return res.redirect('/transfer-asset?success=1'); // ✅ Redirect to main transfer page
    });

  } else if (actionType === 'condemn') {
    const updateSql = `
      UPDATE assets 
      SET status = 'condemned', remarks = ?
      WHERE id = ? AND institution_id = ?
    `;

    db.run(updateSql, [remarks, assetId, institutionId], function (err) {
      if (err) {
        console.error('❌ Condemn update error:', err.message);
        return res.status(500).send('❌ Database error during condemn.');
      }

      const description = `Asset marked as condemned. Remark: ${remarks}`;
      logAudit(assetId, 'Condemn Asset', req.session.user, description);

      return res.redirect('/transfer-asset?success=1'); // ✅ Redirect after successful condemn
    });

  } else {
    return res.redirect(`/transfer-form/${assetId}?error=invalid`);
  }
});

app.get('/report', auth, (req, res) => {
  const { search = '', type = '', department = '' } = req.query;
  const currentUser = req.session.user;
  const institutionId = currentUser.institution_id;

  // Step 1: Fetch the institution's full name
  db.get('SELECT full_name FROM institutions WHERE id = ?', [institutionId], (err, institution) => {
    if (err || !institution) {
      console.error("Error fetching institution name:", err?.message);
      return res.status(500).send("Unable to load report.");
    }

    // Step 2: Prepare SQL query for assets
    let sql = 'SELECT * FROM assets WHERE institution_id = ?';
    const params = [institutionId];

    if (search) {
      sql += ' AND (asset_id LIKE ? OR serial_number LIKE ?)';
      params.push(`%${search}%`, `%${search}%`);
    }

    if (type) {
      sql += ' AND asset_type = ?';
      params.push(type);
    }

    if (department) {
      sql += ' AND department = ?';
      params.push(department);
    }

    // Step 3: Fetch assets
    db.all(sql, params, (err, assets) => {
      if (err) {
        console.error("Error fetching assets:", err.message);
        return res.status(500).send("Error loading assets.");
      }

      // Step 4: Fetch department list for filter dropdown
      db.all('SELECT name FROM departments WHERE institution_id = ?', [institutionId], (err2, departments) => {
        if (err2) {
          console.error("Error fetching departments:", err2.message);
          return res.status(500).send("Error loading departments.");
        }

        // Step 5: Render report page with all necessary data
        res.render('report', {
          assets,
          search,
          type,
          department,
          departments,
          institutionName: institution.full_name,  // ✅ From DB (same as dashboard)
          currentUser                               // ✅ Includes username, role, etc.
        });
      });
    });
  });
});

app.get('/export-assets', auth, (req, res) => {
  const institutionId = req.session.user.institution_id;

  db.all('SELECT * FROM assets WHERE institution_id = ?', [institutionId], async (err, rows) => {
    if (err) {
      console.error('❌ Export error:', err.message);
      return res.status(500).send("Failed to export assets");
    }

    const ExcelJS = require('exceljs');
    const wb = new ExcelJS.Workbook();
    const ws = wb.addWorksheet('Assets');

    if (rows.length > 0) {
      ws.columns = Object.keys(rows[0]).map(k => ({ header: k.toUpperCase(), key: k }));
      rows.forEach(r => ws.addRow(r));
    }

    res.setHeader('Content-Disposition', 'attachment; filename=assets.xlsx');
    res.setHeader('Content-Type', 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet');
    await wb.xlsx.write(res);

    logAudit(null, 'Export Assets', req.session.user, `Exported ${rows.length} assets for institution ID ${institutionId}`);
  });
});

app.get('/preview', auth, (req, res) => {
  const institutionId = req.session.user.institution_id;
  const dept = req.query.department || '';

  // Load departments for the current institution
  db.all('SELECT name FROM departments WHERE institution_id = ?', [institutionId], (e1, depts) => {
    if (e1) return res.status(500).send('Error loading departments');

    if (dept) {
      db.all(
        'SELECT * FROM assets WHERE department = ? AND institution_id = ?',
        [dept, institutionId],
        (e2, a) => {
          if (e2) return res.status(500).send('Error loading assets');
          res.render('preview', {
            departments: depts,
            selectedDepartment: dept,
            assets: a
          });
        }
      );
    } else {
      res.render('preview', {
        departments: depts,
        selectedDepartment: '',
        assets: []
      });
    }
  });
});
function onlyAdmin(req, res, next) {
  if (req.session.user.role === 'admin') {
    return next();
  }
  return res.status(403).render('403', {
    username: req.session.user.username || 'Unknown'
  });
}






app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));

app.use('/', aiRouter); // ✅ Load route
// ✅ IT Director Dashboard: Asset Summary for All Institutions
app.get('/asset-summary', (req, res) => {
  const selectedInstitutionId = parseInt(req.query.institution) || req.session.user?.institution_id || 1;

  // 🔹 Load all institutions for dropdown
  db.all('SELECT id, name FROM institutions ORDER BY name', [], (err, institutions) => {
    if (err || !institutions.length) {
      console.error('❌ Error loading institution list:', err?.message);
      return res.status(500).send("Error loading institution list.");
    }

    const institutionObj = institutions.find(i => i.id === selectedInstitutionId);
    const institutionName = institutionObj?.name || 'Unknown';

    // 🔹 Get total assets count
    db.all(`SELECT COUNT(*) AS total FROM assets WHERE institution_id = ?`, [selectedInstitutionId], (err1, totalRows) => {
      const totalAssets = totalRows?.[0]?.total || 0;

      // 🔹 Count by asset type
      db.all(`
        SELECT asset_type AS type, COUNT(*) AS count 
        FROM assets 
        WHERE institution_id = ? 
        GROUP BY asset_type
      `, [selectedInstitutionId], (err2, typeRows) => {
        const laptopCount = typeRows.find(t => t.type === 'Laptop')?.count || 0;
        const desktopCount = typeRows
          .filter(t => ['PC', 'AIO', 'Desktop'].includes(t.type))
          .reduce((sum, t) => sum + t.count, 0);
        const printerCount = typeRows.find(t => t.type === 'Printer')?.count || 0;

        // 🔹 Count assets out of warranty
        db.all(`
          SELECT COUNT(*) AS count 
          FROM assets 
          WHERE institution_id = ? AND warranty < date('now')
        `, [selectedInstitutionId], (err3, expiredRows) => {
          const outOfWarrantyCount = expiredRows?.[0]?.count || 0;

          // 🔹 Pie chart: Count by status
          db.all(`
            SELECT status, COUNT(*) as count 
            FROM assets 
            WHERE institution_id = ? 
            GROUP BY status
          `, [selectedInstitutionId], (err4, statusRows) => {
            const statusLabels = statusRows.map(r => r.status || 'Unknown');
            const statusData = statusRows.map(r => r.count);

        // 🔹 Department + asset type breakdown for stacked chart
db.all(`
  SELECT department, asset_type, COUNT(*) as count 
  FROM assets 
  WHERE institution_id = ? 
  GROUP BY department, asset_type
`, [selectedInstitutionId], (err5, deptTypeRows) => {
  if (err5) {
    console.error('❌ Error loading department asset breakdown:', err5.message);
    return res.status(500).send("Error loading department breakdown");
  }

  // Step 1: Organize by department
  const deptAssetMap = {};
  const assetTypesSet = new Set();

  deptTypeRows.forEach(({ department, asset_type, count }) => {
    if (!department) return; // skip null departments
    if (!deptAssetMap[department]) deptAssetMap[department] = {};
    deptAssetMap[department][asset_type] = count;
    assetTypesSet.add(asset_type);
  });

  // Step 2: Calculate total assets per department
  const deptTotals = Object.entries(deptAssetMap).map(([dept, assets]) => ({
    dept,
    total: Object.values(assets).reduce((sum, c) => sum + c, 0)
  }));

  // Step 3: Select top 7 departments
  const topDepartments = deptTotals
    .sort((a, b) => b.total - a.total)
    .slice(0, 7)
    .map(d => d.dept);

  const topDeptLabels = topDepartments;

  // 🔸 Simple Bar Chart: total asset count per top department
const topDeptData = topDepartments.map(dept => {
  const assets = deptAssetMap[dept] || {};
  return Object.values(assets).reduce((sum, count) => sum + count, 0);
});


  // Step 4: Normalize asset types list and prepare datasets
  const assetTypes = [...assetTypesSet];
  const stackedDatasets = assetTypes.map(type => ({
    label: type,
    data: topDepartments.map(dept => deptAssetMap[dept]?.[type] || 0),
    backgroundColor: getColorForType(type)
  }));

  // 🔸 Helper to color asset types
  function getColorForType(type) {
    const colorMap = {
      'Laptop': '#42a5f5',
      'PC': '#66bb6a',
      'AIO': '#26c6da',
      'Desktop': '#29b6f6',
      'Printer': '#ffa726',
      'Scanner': '#ef5350',
      'Other': '#ab47bc'
    };
    return colorMap[type] || '#90a4ae'; // default gray
  }





              // 🔹 Condemned model bar chart
              db.all(`
                SELECT model_name, COUNT(*) AS count 
                FROM assets 
                WHERE institution_id = ? AND LOWER(status) = 'condemned' 
                GROUP BY model_name 
                ORDER BY count DESC
              `, [selectedInstitutionId], (err6, condemnedRows) => {
                const condemnedLabels = condemnedRows.map(r => r.model_name || 'Unknown');
                const condemnedData = condemnedRows.map(r => r.count);

                // 🔹 Monthly asset addition trend
                db.all(`
                  SELECT strftime('%m', doi) AS month, COUNT(*) as count 
                  FROM assets 
                  WHERE institution_id = ? 
                  GROUP BY month
                `, [selectedInstitutionId], (err7, trendRows) => {
                  const monthLabels = trendRows.map(r => `Month ${r.month}`);
                  const monthData = trendRows.map(r => r.count);

                  res.render('asset-summary', {
  totalAssets,
  laptopCount,
  desktopCount,
  printerCount,
  outOfWarrantyCount,
  statusLabels,
  statusData,
  topDeptLabels,
  topDeptData,           // ✅ ADD THIS
  stackedDatasets,
  condemnedLabels,
  condemnedData,
  monthLabels,
  monthData,
  institutions,
  selectedInstitution: selectedInstitutionId,
  institutionName,
  currentUser: req.session.user || { username: 'Admin', role: 'admin' }
});
                });
              });
            });
          });
        });
      });
    });
  });

});

// Express route handler for displaying asset lifecycle and audit logs

  // <-- adjust path if needed

const { toIST } = require('./utils');  // Adjust path if needed

app.get('/lifecycle', auth, (req, res) => {
  const search = req.query.search?.trim();
  const user = req.session.user;
  const institutionId = user.institution_id;

  // Step 1: Fetch dropdown asset options
  db.all(
    'SELECT asset_id, serial_number FROM assets WHERE institution_id = ? ORDER BY asset_id ASC',
    [institutionId],
    (err, assetOptions) => {
      if (err) {
        console.error("❌ Error fetching asset options:", err);
        return res.status(500).send("❌ Error fetching asset list");
      }

      // Step 2: If no search term, render blank
      if (!search) {
        return res.render('asset-lifecycle', {
          assetDetails: null,
          lifecycle: [],
          search: '',
          currentUser: user,
          institutionName: user.institution_name || 'Institution',
          toIST,
          assetOptions
        });
      }

      // Step 3: Fetch asset details by asset_id (search)
      db.get(
        'SELECT * FROM assets WHERE asset_id = ? AND institution_id = ?',
        [search, institutionId],
        (assetErr, asset) => {
          if (assetErr) {
            console.error("❌ Error fetching asset:", assetErr);
            return res.status(500).send("❌ Error fetching asset");
          }
          if (!asset) {
            return res.status(404).send("❌ Asset not found");
          }

          const assetPrimaryId = asset.id;

          // Step 4: Fetch audit logs for asset
          db.all(
            `SELECT id, action AS action_type, timestamp, description AS details
             FROM audit_logs
             WHERE asset_id = ? AND institution_id = ?
             ORDER BY id DESC`,
            [assetPrimaryId, institutionId],
            (logErr, auditLogs) => {
              if (logErr) {
                console.error("❌ Error fetching audit logs:", logErr);
                return res.status(500).send("❌ Error loading asset timeline");
              }

              // Debug: Print all audit logs fetched for the asset
              console.log(`Audit logs for asset ${asset.asset_id}:`);
              auditLogs.forEach(log => {
                console.log(`  Log ID ${log.id}: timestamp=${log.timestamp}`);
              });

              // Step 5: Get institution name (with fallback)
              db.get(
                'SELECT name FROM institutions WHERE id = ?',
                [institutionId],
                (instErr, institution) => {
                  const instName = instErr || !institution
                    ? user.institution_name || 'Institution'
                    : institution.name;

                  // (Optional) Add to audit log if asset was just added via ?added=true
                  if (req.query.added === 'true') {
                    logAudit(
                      asset.asset_id,
                      'Add Asset',
                      req.session.user,
                      `✅ New asset (${asset.asset_id}) added by ${req.session.user.username} for institution ${institutionId}`
                    );
                  }

                  // Step 6: Render the asset lifecycle/timeline page
                  res.render('asset-lifecycle', {
                    assetDetails: asset,
                    lifecycle: auditLogs,      // Each: id, action_type, timestamp, details
                    search,
                    currentUser: user,
                    institutionName: instName,
                    toIST,                     // Passed for template date formatting
                    assetOptions
                  });
                }
              );
            }
          );
        }
      );
    }
  );
});

app.get('/support', (req, res) => {
  res.render('support');
});



app.use(express.urlencoded({ extended: true }));
app.use(session({
  secret: 'your-secret', // Use a strong unique secret in production
  resave: false,
  saveUninitialized: true
}));

// Authentication middleware
function auth(req, res, next) {
  if (!req.session.user) return res.redirect('/login');
  next();
}

// Admin-only middleware
function onlyAdmin(req, res, next) {
  if (!req.session.user || req.session.user.role !== 'admin')
    return res.status(403).send('Admins only');
  next();
 }

// UPDATE overdue status
function updateOverdueStatus(cb) {
  db.run(
    `UPDATE pms SET status='overdue' WHERE status='pending' AND scheduled_date < date('now')`,
    [],
    cb || (() => {})
  );
}

// PMS DASHBOARD
app.get('/pms', auth, (req, res) => {
  const user = req.session.user;
  if (!user) return res.redirect('/login');

  updateOverdueStatus();

  if (user.role === 'admin') {
    // ADMIN – show tasks in this institution
    db.all(`
      SELECT p.*, a.asset_id, a.model_name, a.department, a.location
      FROM pms p
      JOIN assets a ON p.asset_id = a.id
      WHERE a.institution_id = ?
      ORDER BY p.scheduled_date ASC
    `, [user.institution_id], (err, tasks) => {
      if (err) return res.status(500).send("DB error loading PMS");

      db.all(`SELECT * FROM users WHERE role='staff' AND institution_id=?`, [user.institution_id], (errStaff, staffUsers) => {
        if (errStaff) return res.status(500).send("Failed to get staff users.");

        db.all(`SELECT * FROM assets WHERE institution_id=?`, [user.institution_id], (err3, assets) => {
          if (err3) return res.status(500).send("Asset fetch error");

          db.all(`SELECT DISTINCT department FROM assets WHERE institution_id=? AND department IS NOT NULL`, [user.institution_id], (err4, departments) => {
            if (err4) return res.status(500).send("Department fetch error");

            // ✅ Calculate stats
            const hasPending = tasks.some(t => t.status === 'pending' || t.status === 'overdue');
            const totalAssets = assets.length;
            const completed = tasks.filter(t => t.status === 'completed').length;
            const remaining = totalAssets - completed;

            // ✅ Get Institution Name safely from session
            const institutionName = user.institution_name || "Unknown Institution";

            // ✅ Render Admin Dashboard
            res.render('pms-admin-dashboard', {
              user,
              currentUser: user,
              tasks,
              alertPMS: hasPending,
              staffUsers,
              assets,
              departments,
              filters: {},
              stats: {
                totalAssets,
                remaining,
                pending: tasks.filter(t => t.status === 'pending').length,
                overdueTasks: tasks.filter(t => t.status === 'overdue').length,
                completed
              },
              pmsList: tasks,
              institutionName, // ✅ Pass correctly
            });
          });
        });
      });
    });
  } 
  
  else if (user.role === 'staff') {
    // STAFF – only show THEIR tasks, include asset user info
    db.all(`
      SELECT p.*, a.asset_id, a.model_name, a.department, a.location, a.user_name
      FROM pms p
      JOIN assets a ON p.asset_id = a.id
      WHERE p.assigned_to = ? AND a.institution_id = ?
      ORDER BY p.scheduled_date ASC
    `, [user.username, user.institution_id], (err, tasks) => {
      if (err) return res.status(500).send("DB error loading PMS (staff)");

      const hasPending = tasks.some(t => t.status === 'pending' || t.status === 'overdue');
      const institutionName = user.institution_name || "Unknown Institution";

      res.render('pms-staff-dashboard', {
        user,
        currentUser: user,
        tasks,
        alertPMS: hasPending,
        institutionName
      });
    });
  } 
  
  else {
    res.status(403).send("Access denied");
  }
});

// Assign PMS to single asset
app.post('/pms/assign', auth, onlyAdmin, (req, res) => {
  const { asset_id, scheduled_date, assigned_to } = req.body;
  const user = req.session.user;

  db.get(`
    SELECT a.id, a.institution_id, u.username 
    FROM assets a 
    JOIN users u ON u.username = ? 
    WHERE a.id = ? AND a.institution_id = u.institution_id AND a.institution_id = ?`,
    [assigned_to, asset_id, user.institution_id],
    (err, row) => {
      if (err || !row) return res.status(400).send("Invalid asset or user");

      // ✅ Avoid duplicate PMS for same asset/date
      db.get(`SELECT id FROM pms WHERE asset_id = ? AND scheduled_date = ?`, [asset_id, scheduled_date], (err2, exists) => {
        if (err2) return res.status(500).send("DB error checking existing PMS");
        if (exists) return res.status(400).send("PMS already scheduled for this date.");

        db.run(
          `INSERT INTO pms (asset_id, scheduled_date, status, assigned_to)
           VALUES (?, ?, 'pending', ?)`,
          [asset_id, scheduled_date, assigned_to],
          function (err3) {
            if (err3) return res.status(500).send("PMS assignment failed");
            res.redirect('/pms');
          }
        );
      });
    }
  );
});


// Department bulk assign
app.post('/pms/assign-dept', auth, onlyAdmin, (req, res) => {
  const { department, scheduled_date, assigned_to } = req.body;
  const user = req.session.user;

  db.all(
    `SELECT id FROM assets 
     WHERE department = ? AND institution_id = ? AND status != 'condemned'`,
    [department, user.institution_id],
    (err, assets) => {
      if (err) return res.status(500).send("Department assets fetch error");
      if (!assets.length) return res.status(400).send('No assets in department or wrong department.');

      const stmt = db.prepare(`
        INSERT INTO pms (asset_id, scheduled_date, status, assigned_to)
        VALUES (?, ?, 'pending', ?)
      `);

      let inserted = 0;
      assets.forEach(a => {
        db.get(`SELECT id FROM pms WHERE asset_id = ? AND scheduled_date = ?`, [a.id, scheduled_date], (errDup, exists) => {
          if (!exists) {
            stmt.run(a.id, scheduled_date, assigned_to);
            inserted++;
          }
        });
      });

      stmt.finalize(() => {
        console.log(`✅ Assigned ${inserted} new PMS tasks.`);
        res.redirect('/pms');
      });
    }
  );
});


// Complete PMS and schedule next one (if not exists)
app.post('/pms/perform/:id', auth, (req, res) => {
  const taskId = req.params.id;
  const username = req.session.user?.username;
  if (!username) return res.status(403).send('Unauthorized');

  const { remarks, condition } = req.body;

  // ✅ First, mark current PMS as completed
  db.run(`
    UPDATE pms
    SET
      status = 'completed',
      completed_date = datetime('now'),
      performed_by = ?,
      remarks = ?,
      condition = ?
    WHERE id = ? AND assigned_to = ?
  `, [username, remarks, condition, taskId, username], function (err) {
    if (err) {
      console.error('❌ Error updating PMS:', err.message);
      return res.status(500).send('Failed to complete PMS task.');
    }

    // Fetch the just-completed PMS to schedule the next one
    db.get(`SELECT asset_id, scheduled_date, assigned_to FROM pms WHERE id = ?`, [taskId], (errTask, task) => {
      if (errTask || !task) return res.redirect('/pms');

      const nextDate = new Date(task.scheduled_date);
      nextDate.setDate(nextDate.getDate() + 180); // +180 days
      const nextScheduledDate = nextDate.toISOString().slice(0, 10);

      // ✅ Avoid scheduling duplicate future PMS
      db.get(`
        SELECT id FROM pms 
        WHERE asset_id = ? AND scheduled_date = ? 
      `, [task.asset_id, nextScheduledDate], (errDup, exists) => {
        if (errDup) {
          console.error('Error checking duplicate PMS:', errDup.message);
          return res.redirect('/pms');
        }

        if (!exists) {
          // Optional: assign next PMS to asset’s responsible user
          db.get(`SELECT user_name FROM assets WHERE id = ?`, [task.asset_id], (errAsset, asset) => {
            const nextAssignedTo = asset?.user_name || task.assigned_to;

            db.run(`
              INSERT INTO pms (asset_id, scheduled_date, status, assigned_to)
              VALUES (?, ?, 'pending', ?)
            `, [task.asset_id, nextScheduledDate, nextAssignedTo], (errIns) => {
              if (errIns) console.error('Error scheduling next PMS:', errIns.message);
              res.redirect('/pms');
            });
          });
        } else {
          // Already exists — don’t insert again
          res.redirect('/pms');
        }
      });
    });
  });
});


// LOGOUT
app.get('/logout', (req, res) => {
  req.session.destroy(() => res.redirect('/login'));
});

// ...rest of your app and error handling


// Start server
app.listen(3000, () => {
  console.log('✅ Server started at: http://localhost:3000');
});


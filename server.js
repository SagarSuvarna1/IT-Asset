// app.js — Complete IT Asset Management w/ RBAC

const express = require('express');
const session = require('express-session');
const bodyParser = require('body-parser');
const sqlite3 = require('sqlite3').verbose();
const ExcelJS = require('exceljs');
const multer = require('multer');
const xlsx = require('xlsx');
const { DateTime } = require('luxon');

function toIST(timestamp) {
  // Convert any input to a Luxon DateTime object safely
  const dt = DateTime.fromJSDate(new Date(timestamp), { zone: 'Asia/Kolkata' });

  // Check if valid
  if (!dt.isValid) return 'Invalid Date';

  return dt.toFormat("dd-MMM-yyyy hh:mm:ss a"); // Example: 06-Jul-2025 03:45:12 PM
}

const path = require('path');


const app = express();
app.locals.toIST = utc =>
  DateTime.fromSQL(utc, { zone: 'utc' })
    .setZone('Asia/Kolkata')
    .toFormat('dd/MM/yyyy, hh:mm:ss a');


const dbPath = path.join(__dirname, 'data', 'it_asset.db'); // ✅ Correct path
const db = new sqlite3.Database(dbPath);
const upload = multer({ dest: 'uploads/' });
app.use(session({
  secret: 'your_secret_key',
  resave: false,
  saveUninitialized: true
}));
app.use(express.static('public'));
app.use(bodyParser.urlencoded({ extended: true }));
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));
app.use(session({ secret: 'it-asset-secure', resave: false, saveUninitialized: true }));

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
app.get('/audit-log', auth, onlyAdmin, (req, res) => {
  const institutionId = req.session.user.institution_id;

  const query = `
    SELECT 
      al.*, 
      i.name AS institution_name
    FROM 
      audit_logs al
    LEFT JOIN 
      institutions i ON al.institution_id = i.id
    WHERE 
      al.institution_id = ?
    ORDER BY 
      al.timestamp DESC
  `;

  db.all(query, [institutionId], (err, rows) => {
    if (err) {
      console.error(err.message);
      return res.status(500).send("Error loading audit logs");
    }

    res.render('audit-log', {
      logs: rows,
      toIST
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

        // Redirect to dashboard
        res.redirect('/dashboard');
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
    'Setting', 'AuditTrial', 'Report', 'Preview', 'Sample', 'Logout'
  ],
  staff: [
    'AddAsset', 'EditAsset', 'TransferAsset', 'Setting', 'Report', 'Logout'
  ]
};

// --- Dashboard & Search ---


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
    const sql = `SELECT * FROM assets WHERE institution_id = ?${query ? ' AND (serial_number LIKE ? OR asset_id LIKE ?)' : ''}`;
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
app.get('/master-management', auth, onlyAdmin, (req, res) => {
  res.render('master-management');
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
  const institutionId = req.session.user.institution_id;

  db.all(
    "SELECT * FROM assets WHERE status='condemned' AND institution_id = ? ORDER BY invoice_date DESC",
    [institutionId],
    (err, rows) => {
      if (err) {
        console.error('❌ Error fetching condemned assets:', err.message);
        return res.status(500).send("Failed to load condemned assets");
      }
      res.render('condemned', { assets: rows });
    }
  );
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
app.get('/bulk-upload', auth, onlyAdmin, (req, res) => {
  res.render('upload', { message: null }); // upload.ejs
});

// GET: Download Excel Template
app.get('/download-template', auth, (req, res) => {
  const filePath = path.join(__dirname, 'uploads', 'asset_template.xlsx');
  res.download(filePath, 'IT_Asset_Upload_Template.xlsx', err => {
    if (err) {
      console.error('❌ Download error:', err.message);
      res.status(500).send('File not found or error downloading.');
    }
  });
});

// POST: Handle Excel Upload
app.post('/upload-assets', auth, onlyAdmin, upload.single('excelFile'), (req, res) => {
  try {
    const filePath = req.file.path;
    const workbook = xlsx.readFile(filePath);
    const sheet = workbook.Sheets[workbook.SheetNames[0]];
    const rows = xlsx.utils.sheet_to_json(sheet);
	const institution_id = req.session.user.institution_id; // ← from login session

    if (!rows || rows.length === 0) {
      return res.render('upload', { message: '❌ Excel file is empty or invalid format.' });
    }

    db.serialize(() => {
      const stmt = db.prepare(`
        INSERT INTO assets (
          asset_type, item_category, item_sub_category, serial_number, asset_id,
          model_name, user_name, processor, location, speed,
          hdd, monitor, ram, ip_address, mac_address,
          warranty, switch_port, switch_ip, port_mark, order_no,
          order_date, doi, invoice_no, invoice_date, cost,
          supplier, ssd, amc, remarks, department,
          status, system_type, pc, pc_type, printer_ip_address,
          amc_warranty, switch_port_no, switch_ip_address,institution_id
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
      `);

      let failedRows = [];

      for (const row of rows) {
        try {
          stmt.run([
            row['Asset Type'], row['Item Category'], row['Item Sub Category'], row['Serial No'], row['Asset ID'],
            row['Model Name'], row['User Name'], row['Processor'], row['Location'], row['Speed'],
            row['HDD'], row['Monitor'], row['RAM'], row['IP Address'], row['MAC Address'],
            row['Warranty'], row['Switch Port'], row['Switch IP'], row['Port Mark'], row['Order No'],
            row['Order Date'], row['DOI'], row['Invoice No'], row['Invoice Date'], row['Cost'],
            row['Supplier'], row['SSD'], row['AMC'], row['Remarks'], row['Department'],
            row['Status'], row['System Type'], row['PC'], row['PC Type'], row['Printer IP Address'],
            row['AMC/Warranty'], row['Switch Port No'], row['Switch IP Address'],institution_id
          ]);
        } catch (err) {
          if (err.message.includes('UNIQUE constraint')) {
            failedRows.push(row['Asset ID'] || row['Serial No']);
          } else {
            console.error("Upload error:", err.message);
            return res.render('upload', { message: '❌ Upload failed: ' + err.message });
          }
        }
      }

      stmt.finalize(() => {
        if (failedRows.length > 0) {
          return res.render('upload', {
            message: `❌ Duplicate found for ${failedRows.length} item(s): ${failedRows.join(', ')}`
          });
        }

         // Audit Trail
		 
    logAudit(null, 'Bulk Upload', req.session.user, `Assets uploaded in bulk by ${req.session.user.username} (Institution: ${req.session.user.institution_name})`);

        res.render('upload', { message: '✅ Bulk upload completed' });
      });
    });

  } catch (error) {
    console.error('❌ Unexpected error during upload:', error.message);
    res.render('upload', { message: '❌ Internal server error during upload.' });
  }
});


// ✅ GET + POST: Add Asset for Institution
app.route('/add-asset')
  .get(auth, (req, res) => {
    const institution_id = req.session.user.institution_id;
    const success = req.query.success === '1';

    db.all("SELECT * FROM departments WHERE institution_id = ?", [institution_id], (err1, departments) => {
      if (err1) return res.status(500).send('Error loading departments');

      db.all("SELECT * FROM models WHERE institution_id = ?", [institution_id], (err2, models) => {
        if (err2) return res.status(500).send('Error loading models');

        db.all("SELECT * FROM locations WHERE institution_id = ? ORDER BY floor, location_name", [institution_id], (err3, locations) => {
          if (err3) return res.status(500).send('Error loading locations');

          res.render('add_asset', {
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
  })

  .post(auth, (req, res) => {
    const formData = req.body;
    const institution_id = req.session.user.institution_id;
    const { serial_number, asset_id } = formData;

    const checkQuery = `
      SELECT * FROM assets WHERE (asset_id = ? OR serial_number = ?) AND institution_id = ?
    `;
    db.get(checkQuery, [asset_id, serial_number, institution_id], (err, existingAsset) => {
      if (err) return res.status(500).send('❌ Error checking for existing asset.');

      if (existingAsset) {
        // Load again form with same data and error message
        db.all("SELECT * FROM departments WHERE institution_id = ?", [institution_id], (err1, departments) => {
          db.all("SELECT * FROM models WHERE institution_id = ?", [institution_id], (err2, models) => {
            db.all("SELECT * FROM locations WHERE institution_id = ?", [institution_id], (err3, locations) => {
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
        values.push(institution_id); // Add institution ID at end

        const insertQuery = `
          INSERT INTO assets (${[...assetFields, 'institution_id'].join(',')})
          VALUES (${[...assetFields, 'institution_id'].map(() => '?').join(',')})
        `;

        db.run(insertQuery, values, function (insertErr) {
          if (insertErr) {
            console.error('❌ Insert error:', insertErr.message);
            return res.status(500).send('❌ Failed to insert asset.');
          }

          // Audit trail
          logAudit(
            asset_id,
            'Add Asset',
            req.session.user,
            `New asset added by ${req.session.user.username} for institution ${institution_id}`
          );

          res.redirect('/add-asset?success=1');
        });
      }
    });
  });

//edit asset
app.get('/edit-asset', auth, (req, res) => {
  const { query, department } = req.query;
  const institution_id = req.session.user.institution_id;

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
    if (err) return res.send('❌ Error fetching assets');

    // Only departments from this institution
    db.all('SELECT name FROM departments WHERE institution_id = ?', [institution_id], (dErr, departments) => {
      if (dErr) return res.send('❌ Error loading departments.');

      res.render('edit-asset', {
        records: rows,
        departments,
        query,
        department
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

// POST Update Asset
app.post('/update/:id', auth, (req, res) => {
  const assetId = req.params.id;
  const institution_id = req.session.user.institution_id;

  // Step 1: Get existing asset (check institution & capture old data)
  db.get('SELECT * FROM assets WHERE id = ? AND institution_id = ?', [assetId, institution_id], (err, oldAsset) => {
    if (err || !oldAsset) {
      return res.status(403).send('❌ Asset not found or access denied.');
    }

    // Step 2: Build updated field values
    const updatedFields = assetFields.map(field => req.body[field]);
    updatedFields.push(assetId); // For WHERE clause

    const sql = `UPDATE assets SET ${assetFields.map(f => `${f} = ?`).join(', ')} WHERE id = ?`;

    db.run(sql, updatedFields, function (updateErr) {
      if (updateErr) {
        console.error('❌ Update failed:', updateErr);
        return res.status(500).send('❌ Update error.');
      }

      // Step 3: Compare old vs new, build log message
      let changes = [];
      for (let field of assetFields) {
        if (oldAsset[field] != req.body[field]) {
          changes.push(`${field}: "${oldAsset[field]}" → "${req.body[field]}"`);
        }
      }

      const changeLog = changes.length > 0
        ? `Updated fields for asset_id ${oldAsset.asset_id}: ` + changes.join(', ')
        : `Updated asset_id ${oldAsset.asset_id} with no changes detected.`;

      // Step 4: Audit log
      logAudit(oldAsset.asset_id, 'Asset Updated', req.session.user, changeLog);

      // Step 5: Redirect back
      res.redirect('/edit-asset');
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

      res.render('transfer-asset', {
        records,
        departments,
        query: q,
        department // 👈 send the selected department
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

        res.render('transfer-form', {
          asset,
          departments,
          locations,
          success: req.query.success === '1',
          error: null
        });
      });
    });
  });
});
app.post('/transfer-form/:id', auth, (req, res) => {
  const assetId = req.params.id;
  const { department, location, status } = req.body;
  const institutionId = req.session.user.institution_id;

  const updateSql = `
    UPDATE assets 
    SET department = ?, location = ?, status = ?
    WHERE id = ? AND institution_id = ?
  `;

  db.run(updateSql, [department, location, status, assetId, institutionId], function (err) {
    if (err) {
      console.error('❌ Transfer update error:', err.message);
      return res.status(500).send('Transfer failed');
    }

    // Log the transfer in audit trail
    logAudit(
      assetId,
      'Transfer Asset',
      req.session.user,
      `Asset transferred to department "${department}", location "${location}", status "${status}"`
    );

    res.redirect(`/transfer-form/${assetId}?success=1`);
  });
});



app.get('/report', auth, (req, res) => {
  const { search = '', type = '', department = '' } = req.query;
  const institutionId = req.session.user.institution_id;

  let sql = 'SELECT * FROM assets WHERE institution_id = ?';
  const ps = [institutionId];

  if (search) {
    sql += ' AND (asset_id LIKE ? OR serial_number LIKE ?)';
    ps.push(`%${search}%`, `%${search}%`);
  }

  if (type) {
    sql += ' AND asset_type = ?';
    ps.push(type);
  }

  if (department) {
    sql += ' AND department = ?';
    ps.push(department);
  }

  db.all(sql, ps, (err, assets) => {
    if (err) return res.status(500).send("Error loading assets");

    db.all('SELECT name FROM departments WHERE institution_id = ?', [institutionId], (err2, depts) => {
      if (err2) return res.status(500).send("Error loading departments");

      res.render('report', {
        assets,
        search,
        type,
        department,
        departments: depts
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
//asset-summary Route – Teste
app.get('/asset-summary', (req, res) => {
  db.all(`SELECT COUNT(*) AS total FROM assets`, [], (err, totalRows) => {
    const totalAssets = totalRows?.[0]?.total || 0;

    // 1. Count asset types
    db.all(`SELECT asset_type AS type, COUNT(*) AS count FROM assets GROUP BY asset_type`, [], (err, typeRows) => {
      if (err) return res.send("Error: Asset Type Query");

      const laptopCount = typeRows.find(t => t.type === 'Laptop')?.count || 0;
      const desktopCount = typeRows.find(t => t.type === 'AIO')?.count || 0;
      const printerCount = typeRows.find(t => t.type === 'Printer')?.count || 0;

      // 2. Out of Warranty (assuming 'warranty' is a DATE)
      db.all(`SELECT COUNT(*) AS count FROM assets WHERE warranty < date('now')`, [], (err, expiredRows) => {
        const outOfWarrantyCount = expiredRows?.[0]?.count || 0;

        // 3. Status Pie Chart
        db.all(`SELECT status, COUNT(*) as count FROM assets GROUP BY status`, [], (err, statusRows) => {
          const statusLabels = statusRows.map(r => r.status);
          const statusData = statusRows.map(r => r.count);

          // 4. Top 6 Departments
          db.all(`SELECT department, COUNT(*) as count FROM assets GROUP BY department ORDER BY count DESC LIMIT 6`, [], (err, deptRows) => {
            const topDeptLabels = deptRows.map(r => r.department);
            const topDeptData = deptRows.map(r => r.count);

            // 5. Condemned Models
            db.all(`SELECT model_name, COUNT(*) AS count
FROM assets
WHERE LOWER(status) = 'condemned'
GROUP BY model_name
ORDER BY count DESC;
`, [], (err, condemnedRows) => {
              const condemnedLabels = condemnedRows.map(r => r.model_name);
              const condemnedData = condemnedRows.map(r => r.count);

              // 6. Monthly Trend (from date of invoice or order date)
              db.all(`SELECT strftime('%m', doi) AS month, COUNT(*) as count FROM assets GROUP BY month`, [], (err, trendRows) => {
                const monthLabels = trendRows.map(r => `Month ${r.month}`);
                const monthData = trendRows.map(r => r.count);

                // Finally render EJS page with all data
              // Finally render EJS page with all data
res.render('asset-summary', {
  totalAssets,
  laptopCount,
  desktopCount,
  printerCount,
  outOfWarrantyCount,
  statusLabels,
  statusData,
  topDeptLabels,
  topDeptData,
  condemnedLabels,
  condemnedData,
  monthLabels,
  monthData,

  // ✅ Add these:
  institutionName: req.session?.institutionName || 'KMC Hospital Attavar',
  currentUser: req.session?.user || { username: 'Sagar', role: 'Admin' }
});

              });
            });
          });
        });
      });
    });
  });
});


// Start server
app.listen(3000, () => {
  console.log('✅ Server started at: http://localhost:3000');
});

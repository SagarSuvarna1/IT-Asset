// app.js — Complete IT Asset Management w/ RBAC

const express = require('express');
const session = require('express-session');
const bodyParser = require('body-parser');
const sqlite3 = require('sqlite3').verbose();
const ExcelJS = require('exceljs');
const multer = require('multer');
const xlsx = require('xlsx');
const { DateTime } = require('luxon');
const path = require('path');

const app = express();
app.locals.toIST = utc =>
  DateTime.fromSQL(utc, { zone: 'utc' })
    .setZone('Asia/Kolkata')
    .toFormat('dd/MM/yyyy, hh:mm:ss a');

const db = new sqlite3.Database('it_asset.db');
const upload = multer({ dest: 'uploads/' });

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
function logAudit(asset_id, action, user, details) {
  db.run(
    `INSERT INTO audit_logs (asset_id, action, performed_by, department, details)
     VALUES (?, ?, ?, ?, ?)`,
    [asset_id, action, user.username, user.department || '-', details],
    err => err && console.error(err)
  );
}

// --- Authentication ---
app.get('/', (req, res) => res.redirect('/login'));
app.get('/login', (req, res) => res.render('login', { error: null }));
app.post('/login', (req, res) => {
  db.get('SELECT * FROM users WHERE username=? AND password=?', [req.body.username, req.body.password], (e, user) => {
    if (e || !user) return res.render('login', { error: 'Invalid credentials' });
    req.session.user = user;
    logAudit(null, 'Login', user, 'User logged in');
    res.redirect('/dashboard');
  });
});
app.get('/logout', auth, (req, res) => {
  logAudit(null, 'Logout', req.session.user, 'User logged out');
  req.session.destroy(() => res.redirect('/login'));
});

// --- Dashboard & Search ---
app.get('/dashboard', auth, (req, res) => {
  const query = req.query.query || '';
  if (!query) return res.render('dashboard', { records: [], query: '' });
  db.all(
    "SELECT * FROM assets WHERE serial_number LIKE ? OR asset_id LIKE ?",
    [`%${query}%`, `%${query}%`],
    (err, records) => {
      if (err) return res.send("Error loading assets.");
      res.render('dashboard', { records, query });
    }
  );
});

// ---- Settings ----
app.get('/settings', auth, (req, res) => res.render('settings', { error: null, success: null }));
app.post('/settings', auth, (req, res) => {
  const { currentPassword, newUsername, newPassword } = req.body;
  db.get('SELECT * FROM users WHERE id=?', [req.session.user.id], (e, u) => {
    if (u.password !== currentPassword)
      return res.render('settings', { error: 'Incorrect current password', success: null });
    db.run('UPDATE users SET username=?, password=? WHERE id=?', [newUsername, newPassword, u.id], () => {
      req.session.user.username = newUsername;
      req.session.user.password = newPassword;
      logAudit(null, 'Settings Updated', req.session.user, 'Credentials changed');
      res.render('settings', { error: null, success: 'Updated successfully' });
    });
  });
});

// ---- Master Management (Admin only) ----
app.get('/master-management', auth, onlyAdmin, (req, res) => {
  res.render('master-management');
});
// --- Master Management Home ---
app.get('/master-management', auth, (req, res) => {
  res.render('master-management');
});

// --- User Management ---
app.get('/users', auth, (req, res) => {
  db.all('SELECT * FROM users', [], (err, users) => {
    if (err) return res.status(500).send('Database error');
    res.render('masters/user-management', { users });
  });
});
app.get('/users/add', auth, (req, res) => {
  res.render('masters/add-user');
});
app.post('/users/add', auth, (req, res) => {
  const { username, email, password, role } = req.body;
  db.run(
    'INSERT INTO users (username, email, password, role) VALUES (?, ?, ?, ?)',
    [username, email, password, role],
    function(err) {
      if (err) return res.status(500).send('Database error');
      logAudit(null, 'User Added', req.session.user, `Added user: ${username} (${email})`);
      res.redirect('/users');
    }
  );
});
app.get('/users/delete/:id', auth, (req, res) => {
  db.get('SELECT username, email FROM users WHERE id = ?', [req.params.id], (err, user) => {
    if (err || !user) return res.status(500).send('User not found');
    db.run('DELETE FROM users WHERE id = ?', [req.params.id], function(err2) {
      if (err2) return res.status(500).send('Delete failed');
      logAudit(null, 'User Deleted', req.session.user, `Deleted user: ${user.username} (${user.email}), id: ${req.params.id}`);
      res.redirect('/users');
    });
  });
});
app.post('/users/role/:id', auth, (req, res) => {
  const { role } = req.body;
  db.get('SELECT username FROM users WHERE id = ?', [req.params.id], (err, user) => {
    if (err || !user) return res.status(500).send('User not found');
    db.run(
      'UPDATE users SET role = ? WHERE id = ?',
      [role, req.params.id],
      function(err2) {
        if (err2) return res.status(500).send('Database error');
        logAudit(null, 'User Role Updated', req.session.user, `Updated user: ${user.username}, id: ${req.params.id}, new role: ${role}`);
        res.redirect('/users');
      }
    );
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

// --- Model Management ---
app.get('/models', auth, (req, res) => {
  db.all('SELECT * FROM models', (err, models) => {
    if (err) return res.status(500).send("DB error");
    res.render('masters/model-management', { models });
  });
});
app.post('/models', auth, (req, res) => {
  const { model_name, category } = req.body;
  db.run('INSERT INTO models (model_name, category) VALUES (?, ?)', [model_name, category], function(err) {
    if (err) return res.status(500).send("Insert failed");
    logAudit(null, 'Add Model', req.session.user, `Added model: ${model_name} (${category})`);
    res.redirect('/models');
  });
});
app.get('/model/delete/:id', auth, (req, res) => {
  db.get('SELECT model_name, category FROM models WHERE id = ?', [req.params.id], (err, model) => {
    if (err || !model) return res.status(500).send('Model not found');
    db.run('DELETE FROM models WHERE id = ?', [req.params.id], function(err2) {
      if (err2) return res.status(500).send('Delete failed');
      logAudit(null, 'Delete Model', req.session.user, `Deleted model: ${model.model_name} (${model.category}), id: ${req.params.id}`);
      res.redirect('/models');
    });
  });
});
app.get('/delete-model/:id', auth, (req, res) => {
  const id = req.params.id;
  db.get('SELECT model_name, category FROM models WHERE id = ?', [id], (err, model) => {
    if (err || !model) return res.status(404).send('Model not found');
    db.run('DELETE FROM models WHERE id = ?', [id], function(err2) {
      if (err2) return res.status(500).send('Delete failed');
      logAudit(null, 'Delete Model', req.session.user, `Deleted model: ${model.model_name} (${model.category}), id: ${id}`);
      res.redirect('/models');
    });
  });
});

// --- Location Management ---
app.get('/locations', auth, (req, res) => {
  db.all('SELECT * FROM locations ORDER BY floor, location_name', (err, locations) => {
    if (err) return res.status(500).send("DB error");
    res.render('masters/location-management', { locations });
  });
});
app.post('/locations', auth, (req, res) => {
  const { floor, location_name } = req.body;
  db.run('INSERT INTO locations (floor, location_name) VALUES (?, ?)', [floor, location_name], function(err) {
    if (err) return res.status(500).send("Insert failed");
    logAudit(null, 'Add Location', req.session.user, `Added location: ${floor} - ${location_name}`);
    res.redirect('/locations');
  });
});
app.get('/location/delete/:id', auth, (req, res) => {
  db.get('SELECT floor, location_name FROM locations WHERE id = ?', [req.params.id], (err, loc) => {
    if (err || !loc) return res.status(500).send('Location not found');
    db.run('DELETE FROM locations WHERE id = ?', [req.params.id], function(err2) {
      if (err2) return res.status(500).send('Delete failed');
      logAudit(null, 'Delete Location', req.session.user, `Deleted location: ${loc.floor} - ${loc.location_name} (id: ${req.params.id})`);
      res.redirect('/locations');
    });
  });
});
// Manage Locations (Custom Management Page)
app.get('/manage-locations', auth, (req, res) => {
  db.all("SELECT * FROM locations ORDER BY floor, location_name", (err, locations) => {
    if (err) return res.status(500).send("Error loading locations");
    res.render('masters/location-management', { locations });
  });
});
app.post('/add-location', auth, (req, res) => {
  const { floor, location_name } = req.body;
  db.run('INSERT INTO locations (floor, location_name) VALUES (?, ?)', [floor, location_name], function(err) {
    if (err) return res.status(500).send('Insert failed');
    logAudit(null, 'Add Location', req.session.user, `Added location: ${floor} - ${location_name}`);
    res.redirect('/locations');
  });
});
app.get('/delete-location/:id', auth, (req, res) => {
  const id = req.params.id;
  db.run("DELETE FROM locations WHERE id = ?", [id], err => {
    if (!err) logAudit(null, 'Delete Location', req.session.user, `Deleted location id: ${id}`);
    if (err) return res.status(500).send("Delete failed");
    res.redirect('/manage-locations');
  });
});
// --- Custom Model Management ---
app.get('/manage-models', auth, (req, res) => {
  db.all("SELECT * FROM models", (err, models) => {
    if (err) return res.status(500).send("Error loading models");
    res.render('masters/model-management', { models });
  });
});

app.post('/add-model', auth, (req, res) => {
  const { model_name, category } = req.body;
  db.run("INSERT INTO models (model_name, category) VALUES (?, ?)", [model_name, category], function(err) {
    if (err) return res.status(500).send("Insert failed");
    logAudit(null, 'Add Model', req.session.user, `Added model: ${model_name} (${category})`);
    res.redirect('/manage-models');
  });
});

app.get('/delete-model/:id', auth, (req, res) => {
  db.get("SELECT model_name, category FROM models WHERE id = ?", [req.params.id], (err, model) => {
    if (err || !model) return res.status(404).send("Model not found");
    db.run("DELETE FROM models WHERE id = ?", [req.params.id], function(err2) {
      if (err2) return res.status(500).send("Delete failed");
      logAudit(null, 'Delete Model', req.session.user, `Deleted model: ${model.model_name} (${model.category}), id: ${req.params.id}`);
      res.redirect('/manage-models');
    });
  });
});


// ---- Audit Logs ----
app.get('/audit-log', auth, onlyAdmin, (req, res) => {
  db.all('SELECT * FROM audit_logs ORDER BY id DESC', (e, logs) => res.render('audit-log', { logs }));
});

// ---- Condemned Assets View ----
app.get('/condemned', auth, onlyAdmin, (req, res) => {
  db.all("SELECT * FROM assets WHERE status='condemned' ORDER BY invoice_date DESC", (err, rows) => {
    if (err) {
      console.error('❌ Error fetching condemned assets:', err.message);
      return res.status(500).send("Failed to load condemned assets");
    }
    res.render('condemned', { assets: rows });
  });
});

app.get('/export-condemned', auth, onlyAdmin, (req, res) => {
  db.all("SELECT * FROM assets WHERE status='condemned'", async (err, rows) => {
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
  });
});

// =================== Bulk Upload ===================

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
          amc_warranty, switch_port_no, switch_ip_address
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
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
            row['AMC/Warranty'], row['Switch Port No'], row['Switch IP Address']
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

        logAudit(null, 'Bulk Upload', req.session.user, `Bulk asset upload`);
        res.render('upload', { message: '✅ Bulk upload completed' });
      });
    });

  } catch (error) {
    console.error('❌ Unexpected error during upload:', error.message);
    res.render('upload', { message: '❌ Internal server error during upload.' });
  }
});

// --- Asset Management ---

// Add Asset
// GET route to render Add Asset form
app.get('/add-asset', auth, (req, res) => {
  db.all("SELECT * FROM departments", [], (err1, departments) => {
    if (err1) return res.status(500).send('Error loading departments');
    db.all("SELECT * FROM models", [], (err2, models) => {
      if (err2) return res.status(500).send('Error loading models');
      db.all("SELECT * FROM locations ORDER BY floor, location_name", [], (err3, locations) => {
        if (err3) return res.status(500).send('Error loading locations');
        res.render('add_asset', { departments, models, locations, success: false });
      });
    });
  });
});

// POST route to handle form submission
app.post('/add-asset', (req, res) => {
  // Simulate success without DB for testing
  const departments = [{ name: 'IT' }];
  const models = [{ model_name: 'Model A', category: 'PC' }];
  const locations = [{ location_name: 'Room 101', floor: '1st Floor' }];

  res.render('add_asset', { departments, models, locations, success: true });
});
// -------- ASSETS (Admin + Staff) --------
const assetFields = [
  'asset_type','item_category','item_sub_category','serial_number','asset_id','model_name',
  'user_name','processor','location','speed','hdd','monitor','ram','ip_address','mac_address',
  'warranty','switch_port','switch_ip','port_mark','order_no','order_date','doi','invoice_no',
  'invoice_date','cost','supplier','ssd','amc','remarks','department','status'
];

app.get('/add-asset', auth, (req, res) =>
  db.all('SELECT name FROM departments', (e1, depts) =>
    db.all('SELECT model_name FROM models', (e2, models) =>
      db.all('SELECT * FROM locations', (e3, locs) =>
        res.render('add_asset', { departments: depts, models, locations: locs, success: false })
      )
    )
  )
);
app.post('/add-asset', auth, (req, res) => {
  const vals = assetFields.map(f => req.body[f]);
  db.run(
    `INSERT INTO assets (${assetFields.join(',')}) VALUES (${assetFields.map(_ => '?').join(',')})`,
    vals,
    err => {
      if (!err) logAudit(req.body.asset_id, 'Added', req.session.user, 'New asset added');
      res.redirect('/dashboard');
    }
  );
});

app.get('/edit-asset', auth, (req, res) => {
  const q = req.query.q || '';
  const dept = req.query.department || '';
  let sql = 'SELECT * FROM assets WHERE 1=1';
  const ps = [];
  if (q) {
    sql += ' AND (serial_number LIKE ? OR asset_id LIKE ?)';
    ps.push(`%${q}%`, `%${q}%`);
  }
  if (dept) {
    sql += ' AND department=?';
    ps.push(dept);
  }
  sql += ' ORDER BY id DESC';
  db.all(sql, ps, (e, rows) => {
    db.all('SELECT name FROM departments', (e2, depts) =>
      res.render('edit-asset', { records: rows, query: q, department: dept, departments: depts })
    );
  });
});

app.get('/edit-form/:id', auth, (req, res) => {
  db.get('SELECT * FROM assets WHERE id=?', [req.params.id], (e1, a) => {
    db.all('SELECT name FROM departments', (e2, depts) =>
      db.all('SELECT model_name FROM models', (e3, models) =>
        db.all('SELECT * FROM locations', (e4, locs) =>
          res.render('edit-form', { asset: a, departments: depts, models, locations: locs })
        )
      )
    );
  });
});

app.post('/update/:id', auth, (req, res) => {
  const vals = assetFields.map(f => req.body[f]);
  vals.push(req.params.id);
  db.run(
    `UPDATE assets SET ${assetFields.map(f => f + '=?').join(',')} WHERE id=?`,
    vals,
    err => {
      if (!err) logAudit(req.body.asset_id, 'Updated', req.session.user, 'Asset updated');
      res.redirect('/edit-asset');
    }
  );
});

app.get('/delete/:id', auth, (req, res) => {
  db.get('SELECT asset_id, model_name, serial_number FROM assets WHERE id=?', [req.params.id], (e, a) => {
    db.run('DELETE FROM assets WHERE id=?', [req.params.id], () => {
      logAudit(a.asset_id, 'Deleted', req.session.user, `Deleted ${a.model_name} (${a.serial_number})`);
      res.redirect('/edit-asset');
    });
  });
});

app.get('/transfer-asset', auth, (req, res) => {
  const q = req.query.q || '';
  const dept = req.query.department || '';
  let sql = 'SELECT * FROM assets WHERE 1=1';
  const ps = [];
  if (q) {
    sql += ' AND (serial_number LIKE ? OR asset_id LIKE ?)';
    ps.push(`%${q}%`, `%${q}%`);
  }
  if (dept) {
    sql += ' AND department=?';
    ps.push(dept);
  }
  sql += ' ORDER BY id DESC';
  db.all(sql, ps, (e, rows) => {
    db.all('SELECT name FROM departments', (e2, depts) =>
      res.render('transfer-asset', { records: rows, query: q, department: dept, departments: depts })
    );
  });
});

app.get('/transfer-form/:id', auth, (req, res) => {
  db.get('SELECT * FROM assets WHERE id=?', [req.params.id], (e1, a) => {
    db.all('SELECT name FROM departments', (e2, depts) =>
      db.all('SELECT * FROM locations', (e3, locs) =>
        res.render('transfer-form', { asset: a, departments: depts, locations: locs })
      )
    );
  });
});

app.post('/transfer/:id', auth, (req, res) => {
  const { department, location, status } = req.body;
  db.get('SELECT asset_id, model_name, serial_number FROM assets WHERE id = ?', [req.params.id], (e, a) => {
    db.run(
      'UPDATE assets SET department=?, location=?, status=? WHERE id=?',
      [department, location, status || 'active', req.params.id],
      () => {
        logAudit(a.asset_id, 'Transferred', req.session.user, `To ${department}/${location}`);
        res.redirect('/transfer-asset');
      }
    );
  });
});

// ---- Report & Export ----
app.get('/report', auth, (req, res) => {
  const { search = '', type = '', department = '' } = req.query;
  let sql = 'SELECT * FROM assets WHERE 1=1';
  const ps = [];
  if (search) {
    sql += ' AND (asset_id LIKE ? OR serial_number LIKE ?)';
    ps.push(`%${search}%`, `%${search}%`);
  }
  if (type) {
    sql += ' AND asset_type=?';
    ps.push(type);
  }
  if (department) {
    sql += ' AND department=?';
    ps.push(department);
  }
  db.all(sql, ps, (e, assets) => {
    db.all('SELECT name FROM departments', (e2, depts) =>
      res.render('report', { assets, search, type, department, departments: depts })
    );
  });
});

app.get('/export-assets', auth, (req, res) => {
  db.all('SELECT * FROM assets', async (e, rows) => {
    const wb = new ExcelJS.Workbook();
    const ws = wb.addWorksheet('Assets');
    ws.columns = Object.keys(rows[0] || {}).map(k => ({ header: k.toUpperCase(), key: k }));
    rows.forEach(r => ws.addRow(r));
    res.setHeader('Content-Disposition', 'attachment; filename=assets.xlsx');
    await wb.xlsx.write(res);
    logAudit(null, 'Export Assets', req.session.user, 'Exported all assets');
  });
});

// ---- Preview ----
app.get('/preview', auth, (req, res) => {
  const dept = req.query.department || '';
  db.all('SELECT name FROM departments', (e1, depts) => {
    if (dept) {
      db.all('SELECT * FROM assets WHERE department=?', [dept], (e2, a) =>
        res.render('preview', { departments: depts, selectedDepartment: dept, assets: a })
      );
    } else {
      res.render('preview', { departments: depts, selectedDepartment: '', assets: [] });
    }
  });
});

// 403
app.get('/403', (req, res) => res.status(403).render('403', { message: 'Access Denied' }));

// Start server
app.listen(3000, () => {
  console.log('✅ Server started at: http://localhost:3000');
});
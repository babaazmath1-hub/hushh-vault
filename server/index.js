const express = require('express');
const cors = require('cors');
require('dotenv').config();

const app = express();
app.use(cors());
app.use(express.json());
app.use(express.static('public'));

app.use('/api/members', require('./routes/members'));
app.use('/api/access',  require('./routes/access'));
app.use('/api/audit',   require('./routes/audit'));

app.listen(process.env.PORT, () =>
  console.log(`Vault running on :${process.env.PORT}`)
);
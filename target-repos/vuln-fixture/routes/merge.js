const express = require('express');
const router = express.Router();
const _ = require('lodash');

router.post('/merge', (req, res) => {
  const target = {};
  _.set(target, req.body.path, req.body.value);
  res.json(target);
});

module.exports = router;
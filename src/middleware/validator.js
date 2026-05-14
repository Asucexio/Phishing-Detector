const { body, validationResult } = require('express-validator');

const validateURL = [
  body('url')
    .notEmpty()
    .withMessage('URL is required')
    .isURL({ require_protocol: true })
    .withMessage('Must be a valid URL with http:// or https://')
    .isLength({ max: 2048 })
    .withMessage('URL too long'),

  (req, res, next) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({
        error: 'Invalid input',
        details: errors.array().map(e => e.msg)
      });
    }
    next();
  }
];

module.exports = { validateURL };

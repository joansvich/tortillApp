module.exports = {
  requireAnon (req, res, next) {
    if (req.session.currentUser) {
      res.redirect('/');
      return;
    }
    next();
  },
  requireUser (req, res, next) {
    if (!req.session.currentUser) {
      res.redirect('/');
      return;
    }
    next();
  },

  requiredFields (req, res, next) {
    const { username, password } = req.body;
    if (!password || !username) {
      res.redirect(`/auth${req.path}`);
      return;
    }
    next();
  }
};

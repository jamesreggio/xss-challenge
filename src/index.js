var fs = require('fs');
var url = require('url');
var jsdom = require('jsdom');
var ejs = require('ejs-mate');
var express = require('express');
var bodyParser = require('body-parser');
var morgan = require('morgan');

var app = express();
app.use(morgan('combined'));
app.use(bodyParser.urlencoded({extended: false}));
app.set('port', process.env.PORT || 3000);
app.set('views', __dirname + '/views');
app.set('view engine', 'ejs');
app.engine('ejs', ejs);

var events = [
  'focus', 'blur',
  'reset', 'submit',
  'resize', 'scroll',
  'keydown', 'keypress', 'keyup',
  'mouseenter', 'mouseover', 'mousemove', 'mousedown', 'mouseup', 'mouseleave',
  'mouseout', 'click', 'dblclick', 'wheel', 'select',
  'error', 'abort', 'load', 'loadstart', 'loadend', 'abort',
];

var bank = {
  routing: '321180379',
  account: '238124938',
  pin: '1111',
};

// Modern browsers are pretty good at detecting inline script detection,
// but this is 1999, baby!
function allowUnsafe(res) {
  return res.header({
    'X-XSS-Protection': 0,
    'Content-Security-Policy': "script-src 'self' 'unsafe-inline'",
  });
}

// In the spirit of the times, let's manually strip HTML tags with a regex.
// What could possibly go wrong?
function sanitizeQuery(query) {
  return Object.keys(query).reduce(function(obj, key) {
    obj[key] = query[key].replace(/<[^>]*>/g, '');
    return obj;
  }, {});
}

app.use('/public', express.static(__dirname + '/../public'));

app.get('/', function(req, res) {
  res.redirect(url.format({
    pathname: 'external_payment',
    query: {
      merchant: 'acct_46a5b98',
      merchant_name: 'Pets.com',
      memo: 'Royal Canin Indoor Light 40 (20lbs)',
      amount: '3999',
    },
  }));
});

app.get('/external_payment', function(req, res) {
  allowUnsafe(res).render('index', {
    query: req.query,
    url: url,
  });
});

app.get('/external_payment/iframe', function(req, res) {
  allowUnsafe(res).render('iframe', {
    query: sanitizeQuery(req.query),
    bank: bank,
  });
});

app.post('/external_payment/iframe', function(req, res) {
  res.render('done');
});

app.post('/stolen_data', function(req, res) {
  var $; // Set by jsdom when loaded.
  var referer = req.get('Referer') || '';

  var challenges = {
    // Ensure the request originated from the browser, and wasn't just a cURL.
    'Valid headers': [10, function() {
      if (!referer) {
        return "You need to solve this with JavaScript; you can't just cURL";
      }
      if (referer.indexOf('/external_payment/iframe') === -1) {
        return 'How did you end up with a Referer like that?';
      }
      return true;
    },],

    // Ensure the stolen bank data matches what was on the page.
    'Correct data': [10, function() {
      for (var key in bank) {
        if (!req.body[key]) {
          return 'Missing "' + key + '"';
        }
        if (req.body[key] !== bank[key]) {
          return 'Incorrect "' + key + '"';
        }
      }
      return true;
    },],

    // Ensure there's actual JavaScript injection occurring.
    'Actual XSS': [50, function() {
      if (!$) {
        return false;
      }

      // I think this is impossible, but if they manage to inject an inline
      // script tag, good on them.
      if ($('script:not([src])').length) {
        return true;
      }

      // The more typical solution is to inject an inline event attribute.
      var eventSelector = events
        .map(function(event) {return '[on' + event + ']';})
        .join(', ');

      if ($(eventSelector).length) {
        return true;
      }

      // Another approach is to redirect the form submission.
      if ($('[action], [formaction]').length) {
        return true;
      }

      return "We couldn't find any evidence of injected JavaScript";
    },],

    // Ensure there's no JavaScript visible to the user.
    'Convincing presentation': [25, function() {
      if (!$) {
        return false;
      }

      var text = $('form').text();
      var button = $('[type="submit"]').val();

      var script = ['script', 'onclick', 'onsubmit', 'onerror', 'onload', '$.'];
      for (var i = 0, term = script[i]; i < script.length; term = script[++i]) {
        if (text.indexOf(term) !== -1 || button.indexOf(term) !== -1) {
          return 'The presence of "' + term + '" seems a bit phishy';
        }
      }

      var html = /<\w|\//;
      if (html.test(text) || html.test(button)) {
        return 'The presence of partial HTML seems a bit phishy';
      }

      return true;
    },],

    // Finally, leave something for the interested hacker.
    'Perfect presentation': [5, function() {
      if (!$) {
        return false;
      }

      var name = $('dl:first-of-type dd:first-of-type').text().trim();
      if (['Pets.com', '"Pets.com"'].indexOf(name) === -1) {
        return 'The recipient name seems a bit off';
      }

      var button = $('[type="submit"]').val().trim();
      if (['Pay', 'Pay Pets.com', 'Pay "Pets.com"'].indexOf(button) === -1) {
        return 'The submit button seems a bit off';
      }

      return true;
    },],
  };

  function scoreChallenges() {
    function pad(str, width) {
      str += '';
      while (width - str.length > 0) {
        str += ' ';
      }
      return str;
    }

    var outcomes = '';
    var scores = Object.keys(challenges).reduce(function(str, key) {
      var challenge = challenges[key];
      var value = challenge[0];
      var outcome = challenge[1]();

      str += pad(outcome === true ? value : 0, 2);
      str += ' / ';
      str += pad(value, 3);
      str += pad(key, 25);
      str += '\n';
      if (typeof outcome === 'string') {
        outcomes += outcome;
        outcomes += '\n';
      }
      return str;
    }, '');

    res.set('Content-Type', 'text/plain');
    res.send(scores + '\n' + outcomes);
  }

  try {
    jsdom.env({
      url: referer,
      src: [fs.readFileSync(__dirname + '/../public/jquery.js')],
      done: function(err, window) {
        $ = window.$;
        scoreChallenges();
      },
    });
  } catch (e) {
    scoreChallenges();
  }
});

app.listen(app.get('port'), function() {
  console.log('xss-challenge is running on port', app.get('port'));
});

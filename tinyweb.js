// tinyweb.js
//
// A modification of Rod Waldhoff's tiny node.js webserver
// original written in coffeescript
// simplified and made more native-ish by Anil Somayaji
// March 19, 2014
//
// original headers of coffeescript version:
//
// A simple static-file web server implemented as a stand-alone
// Node.js/CoffeeScript app.
//---------------------------------------------------------------------
// For more information, see:
// <https://github.com/rodw/tiny-node.js-webserver>
//---------------------------------------------------------------------
// This program is distributed under the "MIT License".
// (See <http://www.opensource.org/licenses/mit-license.php>.)
//---------------------------------------------------------------------
// Copyright (c) 2012 Rodney Waldhoff
//
// Permission is hereby granted, free of charge, to any person
// obtaining a copy of this software and associated documentation
// files (the "Software"), to deal in the Software without restriction,
// including without limitation the rights to use, copy, modify, merge,
// publish, distribute, sublicense, and/or sell copies of the Software,
// and to permit persons to whom the Software is furnished to do so,
// subject to the following conditions:
//
// The above copyright notice and this permission notice shall be
// included in all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
// EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES
// OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
// NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
// BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
// ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
// CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
// THE SOFTWARE.

/*

  Collaboration: Shane Loong
	
  sources:'Tutorial 2' tinywebserver code
      log files hint code
      JSON parsing hint code
      config file hint code

*/
//---------------------------------------------------------------------

var path = require('path');
var http = require('http');
var fs = require('fs');
var Console = require('console').Console;


///console.log('process',process);
console.log('process.env', process.env);

var MIME_TYPES = {
  'c': 'text/plain',
  'css': 'text/css',
  'gif': 'image/gif',
  'h': 'text/plain',
  'htm': 'text/html',
  'html': 'text/html',
  'ico': 'image/x-icon',
  'jpeg': 'image/jpeg',
  'jpg': 'image/jpeg',
  'js': 'text/javascript',
  'json': 'application/json',
  'png': 'image/png',
  'tcl': 'text/plain',
  'txt': 'text/text'

};

// https://github.com/rosszurowski/mime-sniffer/blob/master/lib/numbers.js

var MIME_SNIFF_TYPES = [
  { test: "%PDF", mime: 'application/pdf' },
  //images
  { test: [0x89, 0x50, 0x4e, 0x47], mime: 'image/png' },
  { test: [0xff, 0xd8, 0xff, 0xe0, 0x00, 0x10, 0x4a, 0x46, 0x49, 0x46], mime: 'image/jpeg' },
  { test: [0x47, 0x49, 0x46, 0x38, 0x39, 0x61], mime: 'image/gif' },
  { test: [0x47, 0x49, 0x46, 0x38, 0x37, 0x61], mime: 'image/gif' },
  { offset: 8, test: "WEBPVP8", mime: 'image/webp' },
  { test: "<svg", mime: 'image/svg+xml' },
  { offset: 4, test: 'ftypheic', mime: 'image/heic' },


  //video
  { offset: 4, test: [0x66, 0x74, 0x79, 0x70, 0x6d, 0x70, 0x34], mime: 'video/mp4' },
  { offset: 4, test: [0x66, 0x74, 0x79, 0x70, 0x71, 0x74], mime: 'video/quicktime' },
  { test: [0x1A, 0x45, 0xDF, 0xA3], mime: 'video/webm' },

  //audio
  { test: "ID3", mime: 'audio/mpeg' },
  { test: [0xff, 0xfb], mime: 'audio/mpeg' },


  //html markup
  { test: "<html>", mime: 'text/html' },
  { test: "<!DOCTYPE html>", mime: 'text/html' },


  /* TODO:
// tiff
'49492A00':                     { mime: 'image/tiff', extension: 'tiff' },
'4D4D002A':                     { mime: 'image/tiff', extension: 'tiff' },
// bmp
'424D':                         { mime: 'image/bmp',  extension: 'bmp' },
// webm
'1A45DFA3':                     { mime: 'video/webm', extension: 'webm' },	
// ogg
'4F676753':                     { mime: 'audio/ogg',  extension: 'ogg' },
// flac
'664C6143':                     { mime: 'audio/x-flac', extension: 'flac' },
// wav
'52494646':                     { mime: 'audio/x-wav', extension: 'wav' },

  */
];

MIME_SNIFF_TYPES = MIME_SNIFF_TYPES.map(type => {
  return {
    ...type,
    testBuffer: Buffer.from(type.test)
  }
});

//console.log('MIME_SNIFF', MIME_SNIFF_TYPES);


var sniff_mime = function(content) {
  //let first4 = content.slice(0, 4);
  //console.log('first4', first4);
  for (let i = 0; i < MIME_SNIFF_TYPES.length; i += 1) {
    let type = MIME_SNIFF_TYPES[i];
    let offset = type.offset || 0;
    //https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/Array/slice        
    let firstN = content.slice(offset, offset + type.testBuffer.length);
    console.log('firstN', firstN, 'testBuffer', type.testBuffer, 'type.mime', type.mime);
    if (Buffer.compare(firstN, type.testBuffer) == 0) {
      return type.mime;
    }
  }
  return null;
}

var serve_file = function(request, response, requestpath) {
  return fs.readFile(requestpath, function(error, content) {
    if (error != null) {
      console.error("ERROR: Encountered error while processing " +
        request.method + " of \"" + request.url +
        "\".", error);
      return respond(request, response, 500);
    } else {
      let mime = sniff_mime(content);
      console.log("mime?", mime);
      mime = mime || get_mime(content);
      return respond(request, response, 200,
        content, mime);
    }
  });
};






var default_options = {
  //"host": "localhost",
  "host": "0.0.0.0",
  "port": 80,
  "index": "hello.html",
  "docroot": "/docroot"
}

console.log('default_options', default_options);


var get_mime = function(filename) {
  var ext, type;
  for (ext in MIME_TYPES) {
    type = MIME_TYPES[ext];
    if (filename.indexOf(ext, filename.length - ext.length) !== -1) {
      return type;
    }
  }
  return null;
};


var respond = function(request, response, status, content, content_type) {
  if (!status) {
    status = 200;
  }

  //new 777 status code for when a ducument with the word lucky is in it's URL		
  if (request.url.indexOf("lucky") > -1) {
    status = 777;
  }
  //regular 404 error page
  if (status === 404) {
    content_type = 'text/html';
    console.log("" + status + "\t" +
      request.method + "\t" + request.url);
    content = fs.readFileSync(options.docroot + "/" + 'error404.html');
    response.write(content);
    return response.end();
  }
  if (!content_type) {
    content_type = 'text/plain';
  }
  console.log("" + status + "\t" +
    request.method + "\t" + request.url);
  response.writeHead(status, {
    "Content-Type": content_type
  });
  if (content) {
    response.write(content);
  }
  return response.end();
};

var return_index = function(request, response, requestpath) {

  var exists_callback = function(file_exists) {
    if (file_exists) {
      return serve_file(request, response, requestpath);
    } else {
      return respond(request, response, 404);
    }
  }

  if (requestpath.substr(-1) !== '/') {
    requestpath += "/";
  }
  requestpath += options.index;
  return fs.exists(requestpath, exists_callback);
}

var request_handler = function(request, response) {
  var requestpath;

  if (request.url.match(/((\.|%2E|%2e)(\.|%2E|%2e))|(~|%7E|%7e)/) != null) {
    console.warn("WARNING: " + request.method +
      " of \"" + request.url +
      "\" rejected as insecure.");
    return respond(request, response, 403);
  } else {
    requestpath = path.normalize(path.join(options.docroot, request.url));
    return fs.exists(requestpath, function(file_exists) {
      if (file_exists) {
        return fs.stat(requestpath, function(err, stat) {
          if (err != null) {
            console.error("ERROR: Encountered error calling" +
              "fs.stat on \"" + requestpath +
              "\" while processing " +
              request.method + " of \"" +
              request.url + "\".", err);
            return respond(request, response, 500);
          } else {
            if ((stat != null) && stat.isDirectory()) {
              return return_index(request, response, requestpath);
            } else {
              return serve_file(request, response, requestpath);
            }
          }
        });
      } else {
        return respond(request, response, 404);
      }
    });
  }
};

var server = http.createServer(request_handler);
//comand line argument for configuration file name
var optionsFilename = process.argv[2];

/*
  parsing JSON configuration 
  read json file
  if an error is found in the file it will not use the options there
  default options will be used instead
*/
try {
  options = JSON.parse(fs.readFileSync(optionsFilename, "utf-8"));
  options = {
    ...default_options,
    ...options
  }
} catch (e) {
  if (optionsFilename) {
    console.error("Error reading/parsing options file " + optionsFilename + ", using defaults.");
  } else {
    console.log("No options file specified, using defaults.");
  }
  options = default_options;
}
/*
  creats logfile to print header log
  if there is no logfile then it wil stop the process
*/
try {
  logStream = fs.createWriteStream(options.logfile, { 'flags': 'a' });
} catch (e) {
  logStream = process.stdout;
}
//initialise myConsole for logstream variable 
var myConsole = new Console(logStream);

//console.log('port is', options.port);
server.listen(options.port, options.host, function() {
  return console.log("Server listening at http://" +
    options.host + ":" + options.port + "/");
});

/// <binding AfterBuild='copy-files' ProjectOpened='default' />
/*
This file in the main entry point for defining Gulp tasks and using Gulp plugins.
Click here to learn more. http://go.microsoft.com/fwlink/?LinkId=518007
*/

var gulp = require('gulp'),
rimraf = require('rimraf'),
path = require('path'),
sass = require('gulp-sass'),
fs = require('fs');

// Initialize directory paths.
var paths = {
// Source Directory Paths
nodeModules: "./node_modules/",
scripts: "Scripts/",
styles: "Styles/",
images: "Images/",
wwwroot: "./wwwroot/"
};
// Destination Directory Paths
paths.css = paths.wwwroot + "/css/";
paths.fonts = paths.wwwroot + "/fonts/";
paths.img = paths.wwwroot + "/img/";
paths.js = paths.wwwroot + "/js/";
paths.lib = paths.wwwroot + "/lib/";

gulp.task("clean-lib", function (cb) {
rimraf(paths.lib, cb);
});

gulp.task("copy-lib", ['clean-lib'], function () {
var nodeModules = {
    "bootstrap": "bootstrap/dist/**/bootstrap*.{js,map,css}",
    "bootstrap/fonts": "bootstrap/fonts/*.{,eot,svg,ttf,woff,woff2}",
    "jquery": "jquery/dist/jquery*.{js,map}",
    "jquery-validation": "jquery-validation/dist/jquery.validate.js",
    "jquery-validation-unobtrusive": "jquery-validation-unobtrusive/jquery.validate.unobtrusive.js"
};

for (var destinationDir in nodeModules) {
    gulp.src(paths.nodeModules + nodeModules[destinationDir])
        .pipe(gulp.dest(paths.lib + destinationDir));
}
});

gulp.task('clean-images', function (cb) {
rimraf(paths.img, cb);
});

gulp.task("copy-images", ['clean-images'], function () {
return gulp.src(paths.images + '**/*.{png,jpg,ico,gif}')
    .pipe(gulp.dest(paths.img));
});

gulp.task("sass", function () {
gulp.src(paths.styles + '/*.scss')
    .pipe(sass().on('error', sass.logError))
    .pipe(gulp.dest(paths.css));
});

gulp.task('default', ['copy-lib', 'copy-images', 'sass'], function () {
});
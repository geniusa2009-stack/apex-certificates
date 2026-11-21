FROM mcr.microsoft.com/playwright:v1.49.1-noble
WORKDIR /app
COPY server/package.json server/package-lock.json* server/
RUN cd server && (npm ci --omit=dev || npm install --omit=dev) && npx playwright install chromium
COPY server/ server/
COPY shared/ shared/
COPY _ds/ _ds/
COPY ["APEX Verify.dc.html", "APEX Certificate.dc.html", "APEX Issuance & Security.dc.html", "APEX Volunteer Passport.dc.html", "APEX Certificates Admin.dc.html", "support.js", "./"]
RUN test -f server/fonts/SourceSerif4-Regular.woff2 || (echo "Run server/scripts/vendor-fonts.sh before building" && exit 1)
ENV NODE_ENV=production APEX_WEB_ROOT=/app
USER pwuser
EXPOSE 8080
CMD ["node", "server/src/index.js"]

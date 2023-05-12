'use strict';
// eslint-disable-next-line @typescript-eslint/no-var-requires
var fs = require('fs');
module.exports = {
  async up(queryInterface) {
    const initialSqlScript = fs.readFileSync('src/db/migrations/sql/init.sql', {
      encoding: 'utf-8',
    });
    await queryInterface.sequelize.query(initialSqlScript);
  },

  async down() {
    /**
     * Add reverting commands here.
     *
     * Example:
     * await queryInterface.dropTable('users');
     */
  },
};

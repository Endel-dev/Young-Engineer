const mongoose = require("mongoose");
const AutoIncrement = require("mongoose-sequence")(mongoose);
 
// Define the schema
const appVersionSchema = new mongoose.Schema(
  {
    platform: {
      type: String,
      required: true,
      maxlength: 10,
    },
    version: {
      type: String,
      required: true,
      maxlength: 10,
    },
    url: {
      type: String,
      required: true,
    },
  },
  {
    timestamps: { createdAt: "created_at", updatedAt: false }, // Enable only `created_at`
  }
);
 
// Add auto-incrementing id field
appVersionSchema.plugin(AutoIncrement, { inc_field: "id" });
 
// Create and export the model
const AppVersion = mongoose.model("AppVersion", appVersionSchema);
module.exports = AppVersion;
 
class RenameKeyInVexLicenses < ActiveRecord::Migration[6.1]
  def change
    change_table :vex_licenses do |t|
      t.rename(:key, :license)
    end
  end
end

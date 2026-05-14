const { createClient } = require('@supabase/supabase-js');

const supabase = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_KEY
);

async function testDB() {
  try {
    const { error } = await supabase
      .from('scan_results')
      .select('id')
      .limit(1);

    if (error) throw error;
    console.log('Supabase connected');
  } catch (error) {
    console.error('Supabase connection failed:', error.message);
    process.exit(1);
  }
}

module.exports = { supabase, testDB };